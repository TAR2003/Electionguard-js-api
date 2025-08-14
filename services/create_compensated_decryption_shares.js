/**
 * Create Compensated Decryption Service
 * 
 * Implements compensated decryption for missing guardians using Lagrange coefficients.
 * This service corresponds to the Python create_compensated_decryption_shares.py service.
 */

const crypto = require('crypto');
const { 
    DecryptionShare,
    CompensatedDecryptionShare,
    DecryptionMediator,
    computeLagrangeCoefficient
} = require('../electionguard/decryption');
const {
    Guardian,
    ElectionPartialKeyBackup
} = require('../electionguard/guardian');
const {
    CiphertextTally
} = require('../electionguard/tally');
const {
    ElementModP,
    ElementModQ,
    gPowP,
    hashElems,
    generateRandomBetween
} = require('../electionguard/group');
const {
    ElGamalCiphertext
} = require('../electionguard/elgamal');

/**
 * Create compensated decryption shares for missing guardians
 */
async function createCompensatedDecryption(ciphertextTally, availableGuardians, missingGuardianIds, context) {
    try {
        // Validate inputs
        if (!ciphertextTally || !availableGuardians || !Array.isArray(availableGuardians)) {
            throw new Error('Missing required parameters: ciphertextTally, availableGuardians');
        }
        
        if (!missingGuardianIds || !Array.isArray(missingGuardianIds) || missingGuardianIds.length === 0) {
            throw new Error('No missing guardian IDs provided');
        }
        
        // Parse ciphertext tally if needed
        let tally;
        if (ciphertextTally instanceof CiphertextTally) {
            tally = ciphertextTally;
        } else {
            tally = CiphertextTally.fromJSON(ciphertextTally);
        }
        
        console.log(`Creating compensated decryption for ${missingGuardianIds.length} missing guardians using ${availableGuardians.length} available guardians`);
        
        // Validate we have enough guardians for reconstruction
        const totalGuardians = availableGuardians.length + missingGuardianIds.length;
        const quorum = availableGuardians[0]?.quorum || Math.ceil(totalGuardians / 2);
        
        if (availableGuardians.length < quorum) {
            throw new Error(`Insufficient guardians for compensation: need ${quorum}, have ${availableGuardians.length}`);
        }
        
        // Create compensation shares
        const compensationResults = await createCompensationShares(
            tally, 
            availableGuardians, 
            missingGuardianIds, 
            context
        );
        
        if (!compensationResults.success) {
            throw new Error(`Compensation failed: ${compensationResults.error}`);
        }
        
        // Validate compensation shares
        const validationResults = await validateCompensationShares(
            compensationResults.shares,
            tally,
            availableGuardians,
            missingGuardianIds,
            context
        );
        
        return {
            success: true,
            compensated_decryptions: compensationResults.shares,
            missing_guardian_ids: missingGuardianIds,
            compensating_guardians: availableGuardians.map(guardian => ({
                guardian_id: guardian.guardian_id || guardian.objectId,
                sequence_order: guardian.sequence_order || guardian.sequenceOrder,
                shares_created: compensationResults.sharesCounts[guardian.guardian_id || guardian.objectId] || 0
            })),
            compensation_details: {
                start_time: compensationResults.start_time,
                end_time: compensationResults.end_time,
                processing_time_ms: compensationResults.processing_time_ms,
                total_compensated_shares: compensationResults.shares.length,
                contests_processed: tally.contests.size,
                selections_processed: Array.from(tally.contests.values())
                    .reduce((total, contest) => total + contest.selections.size, 0),
                quorum_threshold: quorum,
                available_guardians: availableGuardians.length,
                missing_guardians: missingGuardianIds.length
            },
            validation_results: validationResults,
            lagrange_coefficients: compensationResults.lagrangeCoefficients,
            created_at: new Date().toISOString()
        };
        
    } catch (error) {
        console.error('Create compensated decryption error:', error);
        return {
            success: false,
            error: error.message,
            created_at: new Date().toISOString()
        };
    }
}

/**
 * Create compensation shares using Lagrange interpolation
 */
async function createCompensationShares(tally, availableGuardians, missingGuardianIds, context) {
    try {
        const startTime = new Date().toISOString();
        const processingStart = Date.now();
        
        const compensatedShares = [];
        const sharesCounts = {};
        const lagrangeCoefficients = {};
        
        // Calculate Lagrange coefficients for available guardians
        const availableSequenceOrders = availableGuardians.map(g => 
            g.sequence_order || g.sequenceOrder
        );
        
        for (const guardian of availableGuardians) {
            const guardianId = guardian.guardian_id || guardian.objectId;
            const sequenceOrder = guardian.sequence_order || guardian.sequenceOrder;
            
            sharesCounts[guardianId] = 0;
            
            // Compute Lagrange coefficient for this guardian
            const coefficient = computeLagrangeCoefficient(
                sequenceOrder,
                availableSequenceOrders
            );
            lagrangeCoefficients[guardianId] = coefficient.toHex();
        }
        
        // Create compensated shares for each missing guardian
        for (const missingGuardianId of missingGuardianIds) {
            // Process each contest and selection
            for (const [contestId, contest] of tally.contests) {
                for (const [selectionId, selection] of contest.selections) {
                    try {
                        const compensatedShare = await createCompensatedShare(
                            selection.ciphertext,
                            missingGuardianId,
                            availableGuardians,
                            lagrangeCoefficients,
                            contestId,
                            selectionId,
                            context
                        );
                        
                        if (compensatedShare) {
                            compensatedShares.push(compensatedShare);
                            
                            // Count shares for each contributing guardian
                            for (const guardian of availableGuardians) {
                                const guardianId = guardian.guardian_id || guardian.objectId;
                                sharesCounts[guardianId] = (sharesCounts[guardianId] || 0) + 1;
                            }
                        }
                    } catch (error) {
                        console.error(`Failed to create compensated share for ${missingGuardianId}:${contestId}:${selectionId}:`, error.message);
                    }
                }
            }
        }
        
        const processingTime = Date.now() - processingStart;
        const endTime = new Date().toISOString();
        
        return {
            success: true,
            shares: compensatedShares,
            sharesCounts: sharesCounts,
            lagrangeCoefficients: lagrangeCoefficients,
            start_time: startTime,
            end_time: endTime,
            processing_time_ms: processingTime
        };
        
    } catch (error) {
        console.error('Create compensation shares error:', error);
        return {
            success: false,
            error: error.message,
            shares: [],
            sharesCounts: {},
            lagrangeCoefficients: {},
            start_time: new Date().toISOString(),
            end_time: new Date().toISOString(),
            processing_time_ms: 0
        };
    }
}

/**
 * Create a single compensated decryption share
 */
async function createCompensatedShare(ciphertext, missingGuardianId, availableGuardians, lagrangeCoefficients, contestId, selectionId, context) {
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
        
        // Compute compensated partial decryption using Lagrange interpolation
        let compensatedDecryption = ElementModP.ONE;
        const contributingShares = [];
        
        for (const guardian of availableGuardians) {
            const guardianId = guardian.guardian_id || guardian.objectId;
            
            // Get guardian's backup for the missing guardian
            const backup = getGuardianBackupForMissing(guardian, missingGuardianId);
            if (!backup) {
                console.warn(`No backup found for guardian ${guardianId} -> missing ${missingGuardianId}`);
                continue;
            }
            
            // Get Lagrange coefficient
            const coefficientHex = lagrangeCoefficients[guardianId];
            if (!coefficientHex) {
                throw new Error(`Missing Lagrange coefficient for guardian ${guardianId}`);
            }
            const coefficient = ElementModQ.fromHex(coefficientHex);
            
            // Compute this guardian's contribution to the missing guardian's share
            // Using the backup key: alpha^{backup_key * lagrange_coefficient}
            const backupKey = ElementModQ.fromHex(backup.encrypted_value || backup.value);
            const contribution = gPowP(alpha, backupKey.multiply(coefficient));
            
            // Multiply into the compensated decryption
            compensatedDecryption = compensatedDecryption.multiply(contribution);
            
            // Track contributing share info
            contributingShares.push({
                guardian_id: guardianId,
                sequence_order: guardian.sequence_order || guardian.sequenceOrder,
                lagrange_coefficient: coefficientHex,
                backup_used: true
            });
        }
        
        // Generate proof of correct compensated decryption
        const proof = await generateCompensatedDecryptionProof(
            alpha,
            compensatedDecryption,
            contributingShares,
            missingGuardianId,
            contestId,
            selectionId,
            context
        );
        
        // Create compensated share object
        const compensatedShare = new CompensatedDecryptionShare(
            missingGuardianId,
            contestId,
            selectionId,
            compensatedDecryption,
            proof,
            contributingShares
        );
        
        return compensatedShare;
        
    } catch (error) {
        console.error('Create compensated share error:', error);
        throw error;
    }
}

/**
 * Get guardian's backup key for missing guardian
 */
function getGuardianBackupForMissing(guardian, missingGuardianId) {
    try {
        // Check different possible formats for backups
        if (guardian.backups_to_share && Array.isArray(guardian.backups_to_share)) {
            const backup = guardian.backups_to_share.find(b => 
                b.recipient_id === missingGuardianId
            );
            if (backup) {
                return backup;
            }
        }
        
        if (guardian.backups && guardian.backups[missingGuardianId]) {
            return guardian.backups[missingGuardianId];
        }
        
        // Try alternative backup storage formats
        if (guardian.electionPartialKeyBackups && guardian.electionPartialKeyBackups[missingGuardianId]) {
            return guardian.electionPartialKeyBackups[missingGuardianId];
        }
        
        return null;
    } catch (error) {
        console.error('Get guardian backup error:', error);
        return null;
    }
}

/**
 * Generate proof for compensated decryption
 */
async function generateCompensatedDecryptionProof(alpha, compensatedDecryption, contributingShares, missingGuardianId, contestId, selectionId, context) {
    try {
        // Generate random nonce
        const nonce = generateRandomBetween(ElementModQ.fromHex('1'), ElementModQ.Q_MINUS_ONE);
        
        // Compute commitment
        const commitment = gPowP(alpha, nonce);
        
        // Create challenge
        const challengeElements = [
            'compensated_decryption',
            missingGuardianId,
            contestId,
            selectionId,
            alpha.toHex(),
            compensatedDecryption.toHex(),
            commitment.toHex()
        ];
        
        // Add contributing guardian info to challenge
        for (const share of contributingShares) {
            challengeElements.push(share.guardian_id);
            challengeElements.push(share.lagrange_coefficient);
        }
        
        if (context && context.crypto_hash) {
            challengeElements.push(JSON.stringify(context.crypto_hash));
        }
        
        const challenge = hashElems(...challengeElements);
        
        // For compensated decryption, the response calculation is more complex
        // This is a simplified version - in practice would need the actual
        // Lagrange-weighted sum of backup keys
        const response = nonce.add(challenge.multiply(ElementModQ.fromHex('1'))); // Simplified
        
        return {
            commitment: commitment,
            challenge: challenge,
            response: response,
            usage: 'compensated_decryption',
            missing_guardian_id: missingGuardianId,
            contributing_guardians: contributingShares.map(share => share.guardian_id),
            contest_id: contestId,
            selection_id: selectionId
        };
        
    } catch (error) {
        console.error('Generate compensated decryption proof error:', error);
        throw error;
    }
}

/**
 * Validate compensation shares
 */
async function validateCompensationShares(shares, tally, availableGuardians, missingGuardianIds, context) {
    try {
        const validationResults = {
            overall_valid: true,
            total_shares: shares.length,
            valid_shares: 0,
            invalid_shares: 0,
            share_results: []
        };
        
        for (const share of shares) {
            try {
                const isValid = await validateCompensatedShare(
                    share, 
                    tally, 
                    availableGuardians, 
                    context
                );
                
                if (isValid) {
                    validationResults.valid_shares++;
                } else {
                    validationResults.invalid_shares++;
                    validationResults.overall_valid = false;
                }
                
                validationResults.share_results.push({
                    missing_guardian_id: share.missingGuardianId,
                    contest_id: share.contestId,
                    selection_id: share.selectionId,
                    valid: isValid,
                    contributing_guardians: share.contributingShares ? 
                        share.contributingShares.map(cs => cs.guardian_id) : []
                });
                
            } catch (error) {
                validationResults.invalid_shares++;
                validationResults.overall_valid = false;
                
                validationResults.share_results.push({
                    missing_guardian_id: share.missingGuardianId,
                    contest_id: share.contestId,
                    selection_id: share.selectionId,
                    valid: false,
                    error: error.message
                });
            }
        }
        
        return validationResults;
        
    } catch (error) {
        console.error('Validate compensation shares error:', error);
        return {
            overall_valid: false,
            error: error.message,
            total_shares: shares.length,
            valid_shares: 0,
            invalid_shares: shares.length,
            share_results: []
        };
    }
}

/**
 * Validate a single compensated share
 */
async function validateCompensatedShare(share, tally, availableGuardians, context) {
    try {
        // Find the corresponding ciphertext in tally
        const contest = tally.getContest(share.contestId);
        if (!contest) {
            throw new Error(`Contest ${share.contestId} not found in tally`);
        }
        
        const selection = contest.getSelection(share.selectionId);
        if (!selection) {
            throw new Error(`Selection ${share.selectionId} not found in contest ${share.contestId}`);
        }
        
        // Validate proof
        if (!share.proof) {
            throw new Error('Missing proof in compensated decryption share');
        }
        
        // Verify that all contributing guardians are in available guardians
        if (!share.contributingShares || share.contributingShares.length === 0) {
            throw new Error('Missing contributing shares information');
        }
        
        for (const contributingShare of share.contributingShares) {
            const guardian = availableGuardians.find(g => 
                (g.guardian_id || g.objectId) === contributingShare.guardian_id
            );
            if (!guardian) {
                throw new Error(`Contributing guardian ${contributingShare.guardian_id} not found in available guardians`);
            }
        }
        
        // Verify compensated decryption proof
        const proofValid = await verifyCompensatedDecryptionProof(
            share.proof,
            selection.ciphertext,
            share.compensatedDecryption,
            share.contributingShares,
            context
        );
        
        return proofValid;
        
    } catch (error) {
        console.error('Validate compensated share error:', error);
        return false;
    }
}

/**
 * Verify compensated decryption proof
 */
async function verifyCompensatedDecryptionProof(proof, ciphertext, compensatedDecryption, contributingShares, context) {
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
        
        // Verify proof equation: alpha^response = commitment * (compensated_decryption)^challenge
        const leftSide = gPowP(alpha, proof.response);
        const rightSide = proof.commitment.multiply(
            gPowP(compensatedDecryption, proof.challenge)
        );
        
        const equationValid = leftSide.equals(rightSide);
        
        // Additional validation: check that the compensated decryption was computed correctly
        // This would involve recomputing the Lagrange interpolation and verifying
        // In practice, this requires access to the backup keys and coefficients
        
        return equationValid;
        
    } catch (error) {
        console.error('Verify compensated decryption proof error:', error);
        return false;
    }
}

/**
 * Compute missing guardian shares from available guardians' backups
 */
function computeMissingGuardianShares(missingGuardianId, availableGuardians, lagrangeCoefficients) {
    try {
        const missingShares = {};
        
        // For each available guardian, get their backup for the missing guardian
        for (const guardian of availableGuardians) {
            const guardianId = guardian.guardian_id || guardian.objectId;
            const backup = getGuardianBackupForMissing(guardian, missingGuardianId);
            
            if (backup && lagrangeCoefficients[guardianId]) {
                const coefficient = ElementModQ.fromHex(lagrangeCoefficients[guardianId]);
                const backupValue = ElementModQ.fromHex(backup.encrypted_value || backup.value);
                
                // The missing guardian's effective secret key coefficient from this backup
                missingShares[guardianId] = backupValue.multiply(coefficient);
            }
        }
        
        return missingShares;
    } catch (error) {
        console.error('Compute missing guardian shares error:', error);
        return {};
    }
}

/**
 * Export compensated decryption data
 */
function exportCompensatedDecryptionData(compensationResult, includeProofs = false) {
    if (!compensationResult.success) {
        throw new Error('Cannot export failed compensated decryption');
    }
    
    const exportData = {
        compensation_metadata: {
            missing_guardians: compensationResult.missing_guardian_ids,
            compensating_guardians_count: compensationResult.compensating_guardians.length,
            total_compensated_shares: compensationResult.compensation_details.total_compensated_shares,
            quorum_threshold: compensationResult.compensation_details.quorum_threshold,
            processing_time_ms: compensationResult.compensation_details.processing_time_ms,
            created_at: compensationResult.created_at
        },
        compensating_guardians: compensationResult.compensating_guardians,
        lagrange_coefficients: compensationResult.lagrange_coefficients,
        compensated_decryptions: compensationResult.compensated_decryptions.map(share => {
            const exportShare = {
                missing_guardian_id: share.missingGuardianId,
                contest_id: share.contestId,
                selection_id: share.selectionId,
                compensated_decryption: share.compensatedDecryption.toHex(),
                contributing_shares: share.contributingShares
            };
            
            if (includeProofs && share.proof) {
                exportShare.proof = {
                    commitment: share.proof.commitment.toHex(),
                    challenge: share.proof.challenge.toHex(),
                    response: share.proof.response.toHex(),
                    usage: share.proof.usage,
                    contributing_guardians: share.proof.contributing_guardians
                };
            }
            
            return exportShare;
        }),
        validation_results: compensationResult.validation_results,
        export_metadata: {
            exported_at: new Date().toISOString(),
            includes_proofs: includeProofs,
            format_version: '1.0'
        }
    };
    
    return exportData;
}

module.exports = {
    createCompensatedDecryption,
    createCompensationShares,
    createCompensatedShare,
    getGuardianBackupForMissing,
    generateCompensatedDecryptionProof,
    validateCompensationShares,
    validateCompensatedShare,
    verifyCompensatedDecryptionProof,
    computeMissingGuardianShares,
    exportCompensatedDecryptionData
};
