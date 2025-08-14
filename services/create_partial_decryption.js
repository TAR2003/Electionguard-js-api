/**
 * Create Partial Decryption Service
 * 
 * Implements partial decryption of encrypted tally using guardian shares.
 * This service corresponds to the Python create_partial_decryption.py service.
 */

const crypto = require('crypto');
const { 
    DecryptionShare,
    CompensatedDecryptionShare,
    DecryptionMediator
} = require('../electionguard/decryption');
const {
    Guardian,
    ElectionPolynomial
} = require('../electionguard/guardian');
const {
    CiphertextTally
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
 * Create partial decryption shares from encrypted tally
 */
async function createPartialDecryption(ciphertextTally, guardians, context, guardianId = null) {
    try {
        // Validate inputs
        if (!ciphertextTally || !guardians || !Array.isArray(guardians)) {
            throw new Error('Missing required parameters: ciphertextTally, guardians');
        }
        
        if (guardians.length === 0) {
            throw new Error('No guardians provided');
        }
        
        // Parse ciphertext tally if needed
        let tally;
        if (ciphertextTally instanceof CiphertextTally) {
            tally = ciphertextTally;
        } else {
            tally = CiphertextTally.fromJSON(ciphertextTally);
        }
        
        // Validate tally structure
        if (!validateTallyForDecryption(tally)) {
            throw new Error('Invalid tally structure for decryption');
        }
        
        // Filter guardians if specific guardian requested
        let activeGuardians = guardians;
        if (guardianId) {
            activeGuardians = guardians.filter(g => 
                (g.guardian_id || g.objectId) === guardianId
            );
            if (activeGuardians.length === 0) {
                throw new Error(`Guardian ${guardianId} not found`);
            }
        }
        
        console.log(`Creating partial decryptions with ${activeGuardians.length} guardians`);
        
        // Create partial decryption shares
        const decryptionResults = await createDecryptionShares(tally, activeGuardians, context);
        
        if (!decryptionResults.success) {
            throw new Error(`Partial decryption failed: ${decryptionResults.error}`);
        }
        
        // Validate all shares
        const validationResults = await validateDecryptionShares(
            decryptionResults.shares, 
            tally, 
            activeGuardians, 
            context
        );
        
        return {
            success: true,
            partial_decryptions: decryptionResults.shares,
            tally_hash: generateTallyHashForDecryption(tally, context),
            guardian_info: activeGuardians.map(guardian => ({
                guardian_id: guardian.guardian_id || guardian.objectId,
                sequence_order: guardian.sequence_order || guardian.sequenceOrder,
                shares_created: decryptionResults.sharesCounts[guardian.guardian_id || guardian.objectId] || 0
            })),
            validation_results: validationResults,
            decryption_details: {
                start_time: decryptionResults.start_time,
                end_time: decryptionResults.end_time,
                processing_time_ms: decryptionResults.processing_time_ms,
                total_shares: decryptionResults.shares.length,
                contests_processed: tally.contests.size,
                selections_processed: Array.from(tally.contests.values())
                    .reduce((total, contest) => total + contest.selections.size, 0)
            },
            created_at: new Date().toISOString()
        };
        
    } catch (error) {
        console.error('Create partial decryption error:', error);
        return {
            success: false,
            error: error.message,
            created_at: new Date().toISOString()
        };
    }
}

/**
 * Validate tally structure for decryption
 */
function validateTallyForDecryption(tally) {
    try {
        // Check basic structure
        if (!tally.contests || tally.contests.size === 0) {
            console.error('Tally has no contests');
            return false;
        }
        
        // Validate each contest
        for (const [contestId, contest] of tally.contests) {
            if (!contest.selections || contest.selections.size === 0) {
                console.error(`Contest ${contestId} has no selections`);
                return false;
            }
            
            // Validate each selection
            for (const [selectionId, selection] of contest.selections) {
                if (!selection.ciphertext || 
                    !selection.ciphertext.alpha || 
                    !selection.ciphertext.beta) {
                    console.error(`Selection ${selectionId} has invalid ciphertext`);
                    return false;
                }
            }
        }
        
        return true;
    } catch (error) {
        console.error('Tally validation error:', error);
        return false;
    }
}

/**
 * Create decryption shares for all guardians
 */
async function createDecryptionShares(tally, guardians, context) {
    try {
        const startTime = new Date().toISOString();
        const processingStart = Date.now();
        
        const allShares = [];
        const sharesCounts = {};
        
        // Process each guardian
        for (const guardian of guardians) {
            const guardianId = guardian.guardian_id || guardian.objectId;
            sharesCounts[guardianId] = 0;
            
            // Create shares for each contest and selection
            for (const [contestId, contest] of tally.contests) {
                for (const [selectionId, selection] of contest.selections) {
                    try {
                        const share = await createSingleDecryptionShare(
                            selection.ciphertext,
                            guardian,
                            contestId,
                            selectionId,
                            context
                        );
                        
                        if (share) {
                            allShares.push(share);
                            sharesCounts[guardianId]++;
                        }
                    } catch (error) {
                        console.error(`Failed to create share for ${guardianId}:${contestId}:${selectionId}:`, error.message);
                    }
                }
            }
        }
        
        const processingTime = Date.now() - processingStart;
        const endTime = new Date().toISOString();
        
        return {
            success: true,
            shares: allShares,
            sharesCounts: sharesCounts,
            start_time: startTime,
            end_time: endTime,
            processing_time_ms: processingTime
        };
        
    } catch (error) {
        console.error('Create decryption shares error:', error);
        return {
            success: false,
            error: error.message,
            shares: [],
            sharesCounts: {},
            start_time: new Date().toISOString(),
            end_time: new Date().toISOString(),
            processing_time_ms: 0
        };
    }
}

/**
 * Create a single decryption share
 */
async function createSingleDecryptionShare(ciphertext, guardian, contestId, selectionId, context) {
    try {
        const guardianId = guardian.guardian_id || guardian.objectId;
        const sequenceOrder = guardian.sequence_order || guardian.sequenceOrder;
        
        // Get guardian's secret key
        let secretKey;
        if (guardian.election_keys && guardian.election_keys.secret_key) {
            if (typeof guardian.election_keys.secret_key === 'string') {
                secretKey = ElementModQ.fromHex(guardian.election_keys.secret_key);
            } else {
                secretKey = guardian.election_keys.secret_key;
            }
        } else if (guardian.electionKeys && guardian.electionKeys.secretKey) {
            secretKey = guardian.electionKeys.secretKey;
        } else {
            throw new Error(`Guardian ${guardianId} missing secret key`);
        }
        
        // Parse ciphertext
        let alpha, beta;
        if (ciphertext instanceof ElGamalCiphertext) {
            alpha = ciphertext.alpha;
            beta = ciphertext.beta;
        } else {
            alpha = ElementModP.fromHex(ciphertext.alpha);
            beta = ElementModP.fromHex(ciphertext.beta);
        }
        
        // Compute partial decryption: M_i = alpha^{s_i}
        const partialDecryption = gPowP(alpha, secretKey);
        
        // Generate proof of correct decryption (Chaum-Pedersen proof)
        const proof = await generateDecryptionProof(
            alpha,
            partialDecryption,
            secretKey,
            guardianId,
            contestId,
            selectionId,
            context
        );
        
        // Create share object
        const share = new DecryptionShare(
            guardianId,
            contestId,
            selectionId,
            partialDecryption,
            proof
        );
        
        return share;
        
    } catch (error) {
        console.error('Create single decryption share error:', error);
        throw error;
    }
}

/**
 * Generate Chaum-Pedersen proof for decryption share
 */
async function generateDecryptionProof(alpha, partialDecryption, secretKey, guardianId, contestId, selectionId, context) {
    try {
        // Generate random nonce
        const nonce = generateRandomBetween(ElementModQ.fromHex('1'), ElementModQ.Q_MINUS_ONE);
        
        // Compute commitments
        const a = gPowP(ElementModP.G, nonce);  // g^r
        const b = gPowP(alpha, nonce);          // alpha^r
        
        // Create challenge
        const challengeElements = [
            guardianId,
            contestId,
            selectionId,
            alpha.toHex(),
            partialDecryption.toHex(),
            a.toHex(),
            b.toHex()
        ];
        
        if (context && context.crypto_hash) {
            challengeElements.push(JSON.stringify(context.crypto_hash));
        }
        
        const challenge = hashElems(...challengeElements);
        
        // Compute response: r + c * s_i mod q
        const response = nonce.add(challenge.multiply(secretKey));
        
        return {
            public_key: gPowP(ElementModP.G, secretKey), // guardian's public key
            commitment_a: a,
            commitment_b: b,
            challenge: challenge,
            response: response,
            usage: 'decryption_share',
            guardian_id: guardianId,
            contest_id: contestId,
            selection_id: selectionId
        };
        
    } catch (error) {
        console.error('Generate decryption proof error:', error);
        throw error;
    }
}

/**
 * Validate decryption shares
 */
async function validateDecryptionShares(shares, tally, guardians, context) {
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
                const isValid = await validateSingleDecryptionShare(share, tally, guardians, context);
                
                if (isValid) {
                    validationResults.valid_shares++;
                } else {
                    validationResults.invalid_shares++;
                    validationResults.overall_valid = false;
                }
                
                validationResults.share_results.push({
                    guardian_id: share.guardianId,
                    contest_id: share.contestId,
                    selection_id: share.selectionId,
                    valid: isValid
                });
                
            } catch (error) {
                validationResults.invalid_shares++;
                validationResults.overall_valid = false;
                
                validationResults.share_results.push({
                    guardian_id: share.guardianId,
                    contest_id: share.contestId,
                    selection_id: share.selectionId,
                    valid: false,
                    error: error.message
                });
            }
        }
        
        return validationResults;
        
    } catch (error) {
        console.error('Validate decryption shares error:', error);
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
 * Validate a single decryption share
 */
async function validateSingleDecryptionShare(share, tally, guardians, context) {
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
        
        // Find guardian
        const guardian = guardians.find(g => 
            (g.guardian_id || g.objectId) === share.guardianId
        );
        if (!guardian) {
            throw new Error(`Guardian ${share.guardianId} not found`);
        }
        
        // Validate proof
        if (!share.proof) {
            throw new Error('Missing proof in decryption share');
        }
        
        // Verify Chaum-Pedersen proof
        const proofValid = await verifyDecryptionProof(
            share.proof,
            selection.ciphertext,
            share.partialDecryption,
            guardian,
            context
        );
        
        return proofValid;
        
    } catch (error) {
        console.error('Validate single decryption share error:', error);
        return false;
    }
}

/**
 * Verify Chaum-Pedersen decryption proof
 */
async function verifyDecryptionProof(proof, ciphertext, partialDecryption, guardian, context) {
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
        
        // Get guardian's public key
        let guardianPublicKey;
        if (guardian.election_keys && guardian.election_keys.public_key) {
            if (typeof guardian.election_keys.public_key === 'string') {
                guardianPublicKey = ElementModP.fromHex(guardian.election_keys.public_key);
            } else {
                guardianPublicKey = guardian.election_keys.public_key;
            }
        } else {
            guardianPublicKey = proof.public_key;
        }
        
        // Verify proof equation: g^response = a * (public_key)^challenge
        const leftSide = gPowP(ElementModP.G, proof.response);
        const rightSide = proof.commitment_a.multiply(
            gPowP(guardianPublicKey, proof.challenge)
        );
        
        const equation1Valid = leftSide.equals(rightSide);
        
        // Verify proof equation: alpha^response = b * (partial_decryption)^challenge  
        const leftSide2 = gPowP(alpha, proof.response);
        const rightSide2 = proof.commitment_b.multiply(
            gPowP(partialDecryption, proof.challenge)
        );
        
        const equation2Valid = leftSide2.equals(rightSide2);
        
        return equation1Valid && equation2Valid;
        
    } catch (error) {
        console.error('Verify decryption proof error:', error);
        return false;
    }
}

/**
 * Generate tally hash for decryption context
 */
function generateTallyHashForDecryption(tally, context) {
    const elements = [tally.objectId];
    
    // Add context hash if available
    if (context && context.crypto_hash) {
        elements.push(JSON.stringify(context.crypto_hash));
    }
    
    // Sort contests for deterministic hash
    const sortedContestIds = Array.from(tally.contests.keys()).sort();
    
    for (const contestId of sortedContestIds) {
        const contest = tally.contests.get(contestId);
        elements.push(contestId);
        
        // Sort selections for deterministic hash
        const sortedSelectionIds = Array.from(contest.selections.keys()).sort();
        
        for (const selectionId of sortedSelectionIds) {
            const selection = contest.selections.get(selectionId);
            elements.push(selectionId);
            elements.push(selection.ciphertext.alpha.toHex());
            elements.push(selection.ciphertext.beta.toHex());
        }
    }
    
    return hashElems(...elements);
}

/**
 * Export partial decryption data
 */
function exportPartialDecryptionData(decryptionResult, includeProofs = false) {
    if (!decryptionResult.success) {
        throw new Error('Cannot export failed partial decryption');
    }
    
    const exportData = {
        decryption_metadata: {
            tally_hash: decryptionResult.tally_hash,
            total_shares: decryptionResult.decryption_details.total_shares,
            guardians_count: decryptionResult.guardian_info.length,
            contests_processed: decryptionResult.decryption_details.contests_processed,
            selections_processed: decryptionResult.decryption_details.selections_processed,
            processing_time_ms: decryptionResult.decryption_details.processing_time_ms,
            created_at: decryptionResult.created_at
        },
        guardian_info: decryptionResult.guardian_info,
        partial_decryptions: decryptionResult.partial_decryptions.map(share => {
            const exportShare = {
                guardian_id: share.guardianId,
                contest_id: share.contestId,
                selection_id: share.selectionId,
                partial_decryption: share.partialDecryption.toHex()
            };
            
            if (includeProofs && share.proof) {
                exportShare.proof = {
                    public_key: share.proof.public_key.toHex(),
                    commitment_a: share.proof.commitment_a.toHex(),
                    commitment_b: share.proof.commitment_b.toHex(),
                    challenge: share.proof.challenge.toHex(),
                    response: share.proof.response.toHex(),
                    usage: share.proof.usage
                };
            }
            
            return exportShare;
        }),
        validation_results: decryptionResult.validation_results,
        export_metadata: {
            exported_at: new Date().toISOString(),
            includes_proofs: includeProofs,
            format_version: '1.0'
        }
    };
    
    return exportData;
}

module.exports = {
    createPartialDecryption,
    validateTallyForDecryption,
    createDecryptionShares,
    createSingleDecryptionShare,
    generateDecryptionProof,
    validateDecryptionShares,
    validateSingleDecryptionShare,
    verifyDecryptionProof,
    generateTallyHashForDecryption,
    exportPartialDecryptionData
};
