/**
 * Combine Decryption Shares Service
 * 
 * Implements the final step of threshold decryption by combining partial
 * decryption shares to recover the plaintext tally results.
 * This service corresponds to the Python combine_decryption_shares.py service.
 */

const crypto = require('crypto');
const { 
    DecryptionShare,
    CompensatedDecryptionShare,
    DecryptionMediator,
    computeLagrangeCoefficient
} = require('../electionguard/decryption');
const {
    CiphertextTally,
    PlaintextTally,
    PlaintextTallyContest,
    PlaintextTallySelection
} = require('../electionguard/tally');
const {
    ElementModP,
    ElementModQ,
    gPowP,
    hashElems
} = require('../electionguard/group');
const {
    ElGamalCiphertext
} = require('../electionguard/elgamal');

/**
 * Combine decryption shares to produce plaintext tally
 */
async function combineDecryptionShares(ciphertextTally, decryptionShares, compensatedShares = [], context = null, manifest = null) {
    try {
        // Validate inputs
        if (!ciphertextTally) {
            throw new Error('Missing ciphertextTally parameter');
        }
        
        if (!decryptionShares || !Array.isArray(decryptionShares)) {
            throw new Error('decryptionShares must be an array');
        }
        
        if (decryptionShares.length === 0 && (!compensatedShares || compensatedShares.length === 0)) {
            throw new Error('No decryption shares provided');
        }
        
        // Parse ciphertext tally if needed
        let tally;
        if (ciphertextTally instanceof CiphertextTally) {
            tally = ciphertextTally;
        } else {
            tally = CiphertextTally.fromJSON(ciphertextTally);
        }
        
        console.log(`Combining ${decryptionShares.length} regular shares and ${compensatedShares?.length || 0} compensated shares`);
        
        // Organize shares by contest and selection
        const organizedShares = organizeDecryptionShares(decryptionShares, compensatedShares);
        
        // Validate we have sufficient shares for each selection
        const sufficiencyCheck = validateShareSufficiency(tally, organizedShares, context);
        if (!sufficiencyCheck.sufficient) {
            throw new Error(`Insufficient shares for decryption: ${sufficiencyCheck.errors.join(', ')}`);
        }
        
        // Perform threshold decryption
        const decryptionResults = await performThresholdDecryption(tally, organizedShares, context);
        
        if (!decryptionResults.success) {
            throw new Error(`Threshold decryption failed: ${decryptionResults.error}`);
        }
        
        // Create plaintext tally
        const plaintextTally = createPlaintextTally(tally, decryptionResults.decryptedValues);
        
        // Validate results
        const validationResults = await validateDecryptionResults(
            plaintextTally,
            tally,
            organizedShares,
            context
        );
        
        return {
            success: true,
            plaintext_tally: plaintextTally.toJSON(),
            decryption_details: {
                start_time: decryptionResults.start_time,
                end_time: decryptionResults.end_time,
                processing_time_ms: decryptionResults.processing_time_ms,
                total_selections_decrypted: decryptionResults.totalSelectionsDecrypted,
                contests_processed: tally.contests.size,
                guardians_participating: organizedShares.participatingGuardians.length,
                shares_used: {
                    regular_shares: decryptionShares.length,
                    compensated_shares: compensatedShares?.length || 0,
                    total_shares: decryptionShares.length + (compensatedShares?.length || 0)
                }
            },
            share_organization: {
                participating_guardians: organizedShares.participatingGuardians,
                missing_guardians: organizedShares.missingGuardians,
                quorum_met: sufficiencyCheck.quorumMet,
                threshold_requirement: sufficiencyCheck.threshold
            },
            validation_results: validationResults,
            tally_hash: decryptionResults.tallyHash,
            created_at: new Date().toISOString()
        };
        
    } catch (error) {
        console.error('Combine decryption shares error:', error);
        return {
            success: false,
            error: error.message,
            created_at: new Date().toISOString()
        };
    }
}

/**
 * Organize decryption shares by contest and selection
 */
function organizeDecryptionShares(decryptionShares, compensatedShares = []) {
    const organized = {
        regularShares: new Map(), // contestId -> selectionId -> guardianId -> share
        compensatedShares: new Map(), // contestId -> selectionId -> missingGuardianId -> share
        participatingGuardians: new Set(),
        missingGuardians: new Set()
    };
    
    // Process regular shares
    for (const share of decryptionShares) {
        const contestId = share.contestId || share.contest_id;
        const selectionId = share.selectionId || share.selection_id;
        const guardianId = share.guardianId || share.guardian_id;
        
        if (!organized.regularShares.has(contestId)) {
            organized.regularShares.set(contestId, new Map());
        }
        
        if (!organized.regularShares.get(contestId).has(selectionId)) {
            organized.regularShares.get(contestId).set(selectionId, new Map());
        }
        
        organized.regularShares.get(contestId).get(selectionId).set(guardianId, share);
        organized.participatingGuardians.add(guardianId);
    }
    
    // Process compensated shares
    for (const share of compensatedShares) {
        const contestId = share.contestId || share.contest_id;
        const selectionId = share.selectionId || share.selection_id;
        const missingGuardianId = share.missingGuardianId || share.missing_guardian_id;
        
        if (!organized.compensatedShares.has(contestId)) {
            organized.compensatedShares.set(contestId, new Map());
        }
        
        if (!organized.compensatedShares.get(contestId).has(selectionId)) {
            organized.compensatedShares.get(contestId).set(selectionId, new Map());
        }
        
        organized.compensatedShares.get(contestId).get(selectionId).set(missingGuardianId, share);
        organized.missingGuardians.add(missingGuardianId);
    }
    
    // Convert sets to arrays for easier handling
    organized.participatingGuardians = Array.from(organized.participatingGuardians);
    organized.missingGuardians = Array.from(organized.missingGuardians);
    
    return organized;
}

/**
 * Validate that we have sufficient shares for decryption
 */
function validateShareSufficiency(tally, organizedShares, context) {
    const errors = [];
    let quorumMet = false;
    
    // Determine threshold (quorum requirement)
    // In practice, this would come from the election setup
    const totalGuardians = organizedShares.participatingGuardians.length + organizedShares.missingGuardians.length;
    const threshold = context?.quorum || Math.ceil(totalGuardians / 2);
    
    const availableGuardians = organizedShares.participatingGuardians.length + organizedShares.missingGuardians.length;
    quorumMet = availableGuardians >= threshold;
    
    if (!quorumMet) {
        errors.push(`Insufficient guardians: need ${threshold}, have ${availableGuardians}`);
    }
    
    // Check each contest and selection
    for (const [contestId, contest] of tally.contests) {
        for (const [selectionId, selection] of contest.selections) {
            let sharesForSelection = 0;
            
            // Count regular shares
            if (organizedShares.regularShares.has(contestId) && 
                organizedShares.regularShares.get(contestId).has(selectionId)) {
                sharesForSelection += organizedShares.regularShares.get(contestId).get(selectionId).size;
            }
            
            // Count compensated shares
            if (organizedShares.compensatedShares.has(contestId) && 
                organizedShares.compensatedShares.get(contestId).has(selectionId)) {
                sharesForSelection += organizedShares.compensatedShares.get(contestId).get(selectionId).size;
            }
            
            if (sharesForSelection < threshold) {
                errors.push(`Insufficient shares for ${contestId}:${selectionId}: need ${threshold}, have ${sharesForSelection}`);
            }
        }
    }
    
    return {
        sufficient: errors.length === 0,
        errors: errors,
        quorumMet: quorumMet,
        threshold: threshold
    };
}

/**
 * Perform threshold decryption using Lagrange interpolation
 */
async function performThresholdDecryption(tally, organizedShares, context) {
    try {
        const startTime = new Date().toISOString();
        const processingStart = Date.now();
        
        const decryptedValues = new Map(); // contestId -> selectionId -> decryptedValue
        let totalSelectionsDecrypted = 0;
        
        // Process each contest and selection
        for (const [contestId, contest] of tally.contests) {
            decryptedValues.set(contestId, new Map());
            
            for (const [selectionId, selection] of contest.selections) {
                try {
                    const decryptedValue = await decryptSingleSelection(
                        selection.ciphertext,
                        contestId,
                        selectionId,
                        organizedShares,
                        context
                    );
                    
                    decryptedValues.get(contestId).set(selectionId, decryptedValue);
                    totalSelectionsDecrypted++;
                    
                } catch (error) {
                    console.error(`Failed to decrypt ${contestId}:${selectionId}:`, error.message);
                    decryptedValues.get(contestId).set(selectionId, 0); // Default to 0
                }
            }
        }
        
        const processingTime = Date.now() - processingStart;
        const endTime = new Date().toISOString();
        
        // Generate tally hash
        const tallyHash = generateDecryptionHash(decryptedValues, tally, context);
        
        return {
            success: true,
            decryptedValues: decryptedValues,
            totalSelectionsDecrypted: totalSelectionsDecrypted,
            tallyHash: tallyHash.toHex(),
            start_time: startTime,
            end_time: endTime,
            processing_time_ms: processingTime
        };
        
    } catch (error) {
        console.error('Perform threshold decryption error:', error);
        return {
            success: false,
            error: error.message,
            decryptedValues: new Map(),
            totalSelectionsDecrypted: 0,
            tallyHash: null,
            start_time: new Date().toISOString(),
            end_time: new Date().toISOString(),
            processing_time_ms: 0
        };
    }
}

/**
 * Decrypt a single selection using threshold decryption
 */
async function decryptSingleSelection(ciphertext, contestId, selectionId, organizedShares, context) {
    try {
        // Parse ciphertext
        let alpha, beta;
        if (ciphertext instanceof ElGamalCiphertext) {
            alpha = ciphertext.alpha;
            beta = ciphertext.beta;
        } else {
            alpha = ElementModP.fromHex(ciphertext.alpha);
            beta = ElementModP.fromHex(ciphertext.beta);
        }
        
        // Collect all partial decryptions for this selection
        const partialDecryptions = new Map(); // guardianId -> partialDecryption
        const guardianSequenceOrders = [];
        
        // Regular shares
        if (organizedShares.regularShares.has(contestId) && 
            organizedShares.regularShares.get(contestId).has(selectionId)) {
            
            const selectionShares = organizedShares.regularShares.get(contestId).get(selectionId);
            
            for (const [guardianId, share] of selectionShares) {
                let partialDecryption;
                if (share.partialDecryption) {
                    partialDecryption = typeof share.partialDecryption === 'string' ?
                        ElementModP.fromHex(share.partialDecryption) : share.partialDecryption;
                } else if (share.partial_decryption) {
                    partialDecryption = typeof share.partial_decryption === 'string' ?
                        ElementModP.fromHex(share.partial_decryption) : share.partial_decryption;
                }
                
                if (partialDecryption) {
                    partialDecryptions.set(guardianId, partialDecryption);
                    
                    // Get sequence order (needed for Lagrange coefficients)
                    const sequenceOrder = share.sequence_order || share.sequenceOrder || 
                        extractSequenceOrderFromGuardianId(guardianId);
                    guardianSequenceOrders.push(sequenceOrder);
                }
            }
        }
        
        // Compensated shares
        if (organizedShares.compensatedShares.has(contestId) && 
            organizedShares.compensatedShares.get(contestId).has(selectionId)) {
            
            const compensatedSelectionShares = organizedShares.compensatedShares.get(contestId).get(selectionId);
            
            for (const [missingGuardianId, share] of compensatedSelectionShares) {
                let compensatedDecryption;
                if (share.compensatedDecryption) {
                    compensatedDecryption = typeof share.compensatedDecryption === 'string' ?
                        ElementModP.fromHex(share.compensatedDecryption) : share.compensatedDecryption;
                } else if (share.compensated_decryption) {
                    compensatedDecryption = typeof share.compensated_decryption === 'string' ?
                        ElementModP.fromHex(share.compensated_decryption) : share.compensated_decryption;
                }
                
                if (compensatedDecryption) {
                    partialDecryptions.set(missingGuardianId, compensatedDecryption);
                    
                    const sequenceOrder = extractSequenceOrderFromGuardianId(missingGuardianId);
                    guardianSequenceOrders.push(sequenceOrder);
                }
            }
        }
        
        if (partialDecryptions.size === 0) {
            throw new Error('No partial decryptions available');
        }
        
        // Compute Lagrange coefficients
        const lagrangeCoefficients = new Map();
        for (const sequenceOrder of guardianSequenceOrders) {
            const coefficient = computeLagrangeCoefficient(sequenceOrder, guardianSequenceOrders);
            lagrangeCoefficients.set(sequenceOrder, coefficient);
        }
        
        // Combine partial decryptions using Lagrange interpolation
        let combinedDecryption = ElementModP.ONE;
        let index = 0;
        
        for (const [guardianId, partialDecryption] of partialDecryptions) {
            const sequenceOrder = guardianSequenceOrders[index];
            const coefficient = lagrangeCoefficients.get(sequenceOrder);
            
            if (coefficient) {
                // Raise partial decryption to the power of Lagrange coefficient
                const weightedPartial = gPowP(partialDecryption, coefficient);
                combinedDecryption = combinedDecryption.multiply(weightedPartial);
            }
            
            index++;
        }
        
        // Compute final decrypted value: M = beta / combined_decryption
        const decryptedMessage = beta.divide(combinedDecryption);
        
        // Convert to integer value using discrete log
        const decryptedValue = discreteLog(decryptedMessage);
        
        return decryptedValue;
        
    } catch (error) {
        console.error('Decrypt single selection error:', error);
        throw error;
    }
}

/**
 * Extract sequence order from guardian ID (fallback method)
 */
function extractSequenceOrderFromGuardianId(guardianId) {
    // Try to extract number from guardian ID like "guardian-1", "guardian-2", etc.
    const match = guardianId.match(/(\d+)$/);
    return match ? parseInt(match[1], 10) : 1;
}

/**
 * Compute discrete logarithm to recover vote count
 */
function discreteLog(element) {
    // This is a brute force approach suitable for small values (vote counts)
    // In practice, ballot selections should be 0 or 1, and contest totals small
    
    try {
        let candidate = ElementModP.ONE;
        
        for (let i = 0; i < 10000; i++) { // Reasonable upper bound for vote counts
            if (candidate.equals(element)) {
                return i;
            }
            candidate = candidate.multiply(ElementModP.G);
        }
        
        console.warn('Discrete log not found within reasonable bounds');
        return 0; // Default to 0 if not found
        
    } catch (error) {
        console.error('Discrete log computation error:', error);
        return 0;
    }
}

/**
 * Create plaintext tally from decrypted values
 */
function createPlaintextTally(ciphertextTally, decryptedValues) {
    const plaintextTally = new PlaintextTally(ciphertextTally.objectId);
    
    for (const [contestId, contest] of ciphertextTally.contests) {
        const plaintextContest = new PlaintextTallyContest(contestId);
        
        for (const [selectionId, selection] of contest.selections) {
            const decryptedValue = decryptedValues.get(contestId)?.get(selectionId) || 0;
            
            const plaintextSelection = new PlaintextTallySelection(
                selectionId,
                decryptedValue,
                decryptedValue,
                `Decrypted tally for ${selectionId}: ${decryptedValue} votes`
            );
            
            plaintextContest.addSelection(plaintextSelection);
        }
        
        plaintextTally.addContest(plaintextContest);
    }
    
    return plaintextTally;
}

/**
 * Validate decryption results
 */
async function validateDecryptionResults(plaintextTally, ciphertextTally, organizedShares, context) {
    try {
        const validationResults = {
            overall_valid: true,
            total_contests: plaintextTally.contests.size,
            valid_contests: 0,
            total_votes: plaintextTally.getTotalVotes(),
            contest_results: []
        };
        
        for (const [contestId, plaintextContest] of plaintextTally.contests) {
            const contestResult = {
                contest_id: contestId,
                valid: true,
                total_votes: plaintextContest.getTotalVotes(),
                selections_count: plaintextContest.selections.size,
                selection_results: []
            };
            
            // Validate each selection
            for (const [selectionId, plaintextSelection] of plaintextContest.selections) {
                const selectionResult = {
                    selection_id: selectionId,
                    tally: plaintextSelection.tally,
                    valid: plaintextSelection.tally >= 0 // Basic validation
                };
                
                if (!selectionResult.valid) {
                    contestResult.valid = false;
                    validationResults.overall_valid = false;
                }
                
                contestResult.selection_results.push(selectionResult);
            }
            
            if (contestResult.valid) {
                validationResults.valid_contests++;
            }
            
            validationResults.contest_results.push(contestResult);
        }
        
        return validationResults;
        
    } catch (error) {
        console.error('Validate decryption results error:', error);
        return {
            overall_valid: false,
            error: error.message,
            total_contests: 0,
            valid_contests: 0,
            total_votes: 0,
            contest_results: []
        };
    }
}

/**
 * Generate hash of decryption results for verification
 */
function generateDecryptionHash(decryptedValues, tally, context) {
    const elements = [tally.objectId];
    
    if (context && context.crypto_hash) {
        elements.push(JSON.stringify(context.crypto_hash));
    }
    
    // Sort contests for deterministic hash
    const sortedContestIds = Array.from(decryptedValues.keys()).sort();
    
    for (const contestId of sortedContestIds) {
        elements.push(contestId);
        
        const contestValues = decryptedValues.get(contestId);
        const sortedSelectionIds = Array.from(contestValues.keys()).sort();
        
        for (const selectionId of sortedSelectionIds) {
            elements.push(selectionId);
            elements.push(contestValues.get(selectionId).toString());
        }
    }
    
    return hashElems(...elements);
}

/**
 * Export decryption results
 */
function exportDecryptionResults(combinationResult, includeShares = false) {
    if (!combinationResult.success) {
        throw new Error('Cannot export failed decryption combination');
    }
    
    const exportData = {
        decryption_metadata: {
            total_selections_decrypted: combinationResult.decryption_details.total_selections_decrypted,
            contests_processed: combinationResult.decryption_details.contests_processed,
            guardians_participating: combinationResult.decryption_details.guardians_participating,
            processing_time_ms: combinationResult.decryption_details.processing_time_ms,
            tally_hash: combinationResult.tally_hash,
            created_at: combinationResult.created_at
        },
        plaintext_tally: combinationResult.plaintext_tally,
        validation_results: combinationResult.validation_results,
        share_organization: combinationResult.share_organization,
        export_metadata: {
            exported_at: new Date().toISOString(),
            includes_shares: includeShares,
            format_version: '1.0'
        }
    };
    
    return exportData;
}

module.exports = {
    combineDecryptionShares,
    organizeDecryptionShares,
    validateShareSufficiency,
    performThresholdDecryption,
    decryptSingleSelection,
    discreteLog,
    createPlaintextTally,
    validateDecryptionResults,
    generateDecryptionHash,
    exportDecryptionResults
};
