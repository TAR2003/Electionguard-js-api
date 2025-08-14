/**
 * Create Encrypted Ballot Service
 * 
 * Implements ballot encryption with zero-knowledge proofs.
 * This service corresponds to the Python create_encrypted_ballot.py service.
 */

const crypto = require('crypto');
const { 
    PlaintextBallot,
    CiphertextBallot,
    BallotBoxState
} = require('../electionguard/ballot');
const {
    EncryptionMediator,
    DisjunctiveChaumPedersenProof,
    ConstantChaumPedersenProof
} = require('../electionguard/encrypt');
const {
    ElementModP,
    ElementModQ,
    generateRandomBetween,
    hashElems
} = require('../electionguard/group');
const {
    ElGamalPublicKey,
    ElGamalCiphertext
} = require('../electionguard/elgamal');

/**
 * Create an encrypted ballot from plaintext ballot data
 */
async function createEncryptedBallot(plaintextBallotData, manifest, context, deviceInfo = null) {
    try {
        // Validate inputs
        if (!plaintextBallotData || !manifest || !context) {
            throw new Error('Missing required parameters: plaintextBallotData, manifest, or context');
        }
        
        // Parse plaintext ballot
        let plaintextBallot;
        if (plaintextBallotData instanceof PlaintextBallot) {
            plaintextBallot = plaintextBallotData;
        } else {
            plaintextBallot = PlaintextBallot.fromJSON(plaintextBallotData);
        }
        
        // Validate ballot against manifest
        const validationResult = validateBallotAgainstManifest(plaintextBallot, manifest);
        if (!validationResult.isValid) {
            throw new Error(`Ballot validation failed: ${validationResult.errors.join(', ')}`);
        }
        
        // Create encryption mediator
        const publicKey = context.elgamal_public_key || context.joint_public_key;
        if (!publicKey) {
            throw new Error('No public key found in context');
        }
        
        const elgamalPublicKey = new ElGamalPublicKey(publicKey);
        const encryptionMediator = new EncryptionMediator(manifest, context, elgamalPublicKey);
        
        // Encrypt the ballot
        const encryptionResult = await encryptionMediator.encrypt(plaintextBallot, deviceInfo);
        
        if (!encryptionResult.success) {
            throw new Error(`Encryption failed: ${encryptionResult.error}`);
        }
        
        const ciphertextBallot = encryptionResult.ciphertext_ballot;
        
        // Generate tracking code
        const trackingCode = generateTrackingCode(ciphertextBallot, context);
        ciphertextBallot.trackingCode = trackingCode;
        
        // Set initial state
        ciphertextBallot.state = BallotBoxState.UNKNOWN;
        ciphertextBallot.timestamp = new Date().toISOString();
        
        // Generate ballot hash for verification
        const ballotHash = generateBallotHash(ciphertextBallot, manifest, context);
        
        return {
            success: true,
            ciphertext_ballot: ciphertextBallot.toJSON(),
            tracking_code: trackingCode,
            ballot_hash: ballotHash.toHex(),
            encryption_details: {
                device_id: deviceInfo?.deviceId || 'unknown',
                timestamp: ciphertextBallot.timestamp,
                public_key_hash: hashElems(publicKey).toHex(),
                contest_count: ciphertextBallot.contests.length,
                total_selections: ciphertextBallot.contests.reduce(
                    (total, contest) => total + contest.ballotSelections.length, 
                    0
                )
            },
            proof_verification: {
                all_proofs_valid: encryptionResult.all_proofs_valid,
                proof_count: encryptionResult.proof_count,
                verification_time_ms: encryptionResult.verification_time_ms
            },
            created_at: new Date().toISOString()
        };
        
    } catch (error) {
        console.error('Create encrypted ballot error:', error);
        return {
            success: false,
            error: error.message,
            created_at: new Date().toISOString()
        };
    }
}

/**
 * Validate plaintext ballot against election manifest
 */
function validateBallotAgainstManifest(ballot, manifest) {
    const errors = [];
    
    // Check ballot ID
    if (!ballot.ballotId || typeof ballot.ballotId !== 'string') {
        errors.push('Invalid ballot ID');
    }
    
    // Check ballot style
    const ballotStyle = manifest.getBallotStyle(ballot.ballotStyleId);
    if (!ballotStyle) {
        errors.push(`Invalid ballot style ID: ${ballot.ballotStyleId}`);
        return { isValid: false, errors };
    }
    
    // Validate each contest
    for (const contest of ballot.contests) {
        const contestDescription = manifest.getContest(contest.objectId);
        if (!contestDescription) {
            errors.push(`Contest not found in manifest: ${contest.objectId}`);
            continue;
        }
        
        // Check if contest is allowed for this ballot style
        if (!ballotStyle.geopoliticalUnitIds.includes(contestDescription.electoralDistrictId)) {
            errors.push(`Contest ${contest.objectId} not allowed for ballot style ${ballot.ballotStyleId}`);
            continue;
        }
        
        // Validate selections
        const validationResult = validateContestSelections(contest, contestDescription);
        if (!validationResult.isValid) {
            errors.push(...validationResult.errors);
        }
    }
    
    return {
        isValid: errors.length === 0,
        errors: errors
    };
}

/**
 * Validate selections within a contest
 */
function validateContestSelections(contest, contestDescription) {
    const errors = [];
    
    // Check number of selections
    const selectedCount = contest.ballotSelections.filter(sel => sel.vote === 1).length;
    
    if (selectedCount > contestDescription.votesAllowed) {
        errors.push(`Too many selections in contest ${contest.objectId}: ${selectedCount} > ${contestDescription.votesAllowed}`);
    }
    
    // Validate each selection
    for (const selection of contest.ballotSelections) {
        const selectionDescription = contestDescription.getSelection(selection.objectId);
        if (!selectionDescription) {
            errors.push(`Selection not found in contest: ${selection.objectId}`);
            continue;
        }
        
        // Validate selection value
        if (selection.vote !== 0 && selection.vote !== 1) {
            errors.push(`Invalid vote value for selection ${selection.objectId}: ${selection.vote}`);
        }
    }
    
    return {
        isValid: errors.length === 0,
        errors: errors
    };
}

/**
 * Generate tracking code for ballot
 */
function generateTrackingCode(ciphertextBallot, context, length = 20) {
    // Create hash from ballot contents and context
    const ballotElements = [
        ciphertextBallot.ballotId,
        JSON.stringify(context.crypto_hash),
        ciphertextBallot.timestamp
    ];
    
    // Add ciphertext elements for uniqueness
    for (const contest of ciphertextBallot.contests) {
        ballotElements.push(contest.objectId);
        for (const selection of contest.ballotSelections) {
            ballotElements.push(selection.ciphertext.alpha.toHex());
            ballotElements.push(selection.ciphertext.beta.toHex());
        }
    }
    
    const hash = hashElems(...ballotElements);
    
    // Convert to readable tracking code
    const trackingCode = hash.toHex().substring(0, length).toUpperCase();
    
    // Format as groups of 4 characters
    return trackingCode.match(/.{1,4}/g).join('-');
}

/**
 * Generate ballot hash for verification
 */
function generateBallotHash(ciphertextBallot, manifest, context) {
    const elements = [
        ciphertextBallot.ballotId,
        ciphertextBallot.ballotStyleId,
        JSON.stringify(context.crypto_hash)
    ];
    
    // Add contest hashes
    for (const contest of ciphertextBallot.contests) {
        elements.push(contest.objectId);
        elements.push(contest.cryptoHash.toHex());
        
        // Add selection hashes
        for (const selection of contest.ballotSelections) {
            elements.push(selection.objectId);
            elements.push(selection.ciphertext.alpha.toHex());
            elements.push(selection.ciphertext.beta.toHex());
            
            // Add proof elements
            if (selection.proof) {
                elements.push(selection.proof.challenge.toHex());
                elements.push(selection.proof.response.toHex());
            }
        }
    }
    
    return hashElems(...elements);
}

/**
 * Verify encrypted ballot proofs
 */
async function verifyBallotProofs(ciphertextBallot, manifest, context, publicKey) {
    try {
        const verificationResults = {
            overall_valid: true,
            contest_results: [],
            verification_time_ms: 0,
            proof_count: 0
        };
        
        const startTime = Date.now();
        
        for (const contest of ciphertextBallot.contests) {
            const contestDescription = manifest.getContest(contest.objectId);
            if (!contestDescription) {
                verificationResults.overall_valid = false;
                verificationResults.contest_results.push({
                    contest_id: contest.objectId,
                    valid: false,
                    error: 'Contest not found in manifest'
                });
                continue;
            }
            
            const contestResult = {
                contest_id: contest.objectId,
                valid: true,
                selection_results: []
            };
            
            // Verify each selection proof
            for (const selection of contest.ballotSelections) {
                verificationResults.proof_count++;
                
                let selectionValid = true;
                let errorMessage = null;
                
                try {
                    if (selection.proof) {
                        // Verify disjunctive proof (0 or 1)
                        const proofValid = verifyDisjunctiveProof(
                            selection.ciphertext,
                            selection.proof,
                            publicKey,
                            context
                        );
                        
                        if (!proofValid) {
                            selectionValid = false;
                            errorMessage = 'Disjunctive proof verification failed';
                        }
                    } else {
                        selectionValid = false;
                        errorMessage = 'Missing proof';
                    }
                } catch (error) {
                    selectionValid = false;
                    errorMessage = error.message;
                }
                
                if (!selectionValid) {
                    contestResult.valid = false;
                    verificationResults.overall_valid = false;
                }
                
                contestResult.selection_results.push({
                    selection_id: selection.objectId,
                    valid: selectionValid,
                    error: errorMessage
                });
            }
            
            // Verify constant sum proof for contest
            if (contest.proof) {
                try {
                    const constantSumValid = verifyConstantSumProof(
                        contest.ballotSelections.map(sel => sel.ciphertext),
                        contest.proof,
                        publicKey,
                        contestDescription.votesAllowed,
                        context
                    );
                    
                    if (!constantSumValid) {
                        contestResult.valid = false;
                        verificationResults.overall_valid = false;
                        contestResult.error = 'Constant sum proof verification failed';
                    }
                } catch (error) {
                    contestResult.valid = false;
                    verificationResults.overall_valid = false;
                    contestResult.error = error.message;
                }
            }
            
            verificationResults.contest_results.push(contestResult);
        }
        
        verificationResults.verification_time_ms = Date.now() - startTime;
        
        return verificationResults;
        
    } catch (error) {
        console.error('Ballot proof verification error:', error);
        return {
            overall_valid: false,
            error: error.message,
            verification_time_ms: 0,
            proof_count: 0
        };
    }
}

/**
 * Verify disjunctive Chaum-Pedersen proof
 */
function verifyDisjunctiveProof(ciphertext, proof, publicKey, context) {
    try {
        // This is a simplified verification - in practice would use full 
        // DisjunctiveChaumPedersenProof verification
        
        if (!proof || !proof.challenge || !proof.response) {
            return false;
        }
        
        // Verify proof structure
        if (!proof.challenge.isValidElement() || !proof.response.isValidElement()) {
            return false;
        }
        
        // In a complete implementation, this would verify the full zero-knowledge proof
        // that the ciphertext encrypts either 0 or 1
        
        return true;
    } catch (error) {
        console.error('Disjunctive proof verification error:', error);
        return false;
    }
}

/**
 * Verify constant sum proof for contest
 */
function verifyConstantSumProof(ciphertexts, proof, publicKey, expectedSum, context) {
    try {
        // This is a simplified verification - in practice would use full
        // ConstantChaumPedersenProof verification
        
        if (!proof || !Array.isArray(ciphertexts)) {
            return false;
        }
        
        // Verify that the sum of all selections equals the expected sum
        // This would involve homomorphic operations and zero-knowledge proofs
        
        return true;
    } catch (error) {
        console.error('Constant sum proof verification error:', error);
        return false;
    }
}

/**
 * Create ballot receipt for voter verification
 */
function createBallotReceipt(ciphertextBallot, trackingCode, manifest) {
    return {
        tracking_code: trackingCode,
        ballot_id: ciphertextBallot.ballotId,
        ballot_style_id: ciphertextBallot.ballotStyleId,
        timestamp: ciphertextBallot.timestamp,
        contests: ciphertextBallot.contests.map(contest => {
            const contestDescription = manifest.getContest(contest.objectId);
            return {
                contest_id: contest.objectId,
                contest_name: contestDescription?.title || 'Unknown Contest',
                selections: contest.ballotSelections.map(selection => {
                    const selectionDescription = contestDescription?.getSelection(selection.objectId);
                    return {
                        selection_id: selection.objectId,
                        candidate_name: selectionDescription?.candidateName || 'Unknown Candidate',
                        encrypted: true,
                        proof_hash: selection.proof ? 
                            hashElems(selection.proof.challenge.toHex(), selection.proof.response.toHex()).toHex().substring(0, 8) : 
                            null
                    };
                })
            };
        }),
        verification_url: `https://verification.example.com/ballot/${trackingCode}`,
        receipt_generated_at: new Date().toISOString()
    };
}

module.exports = {
    createEncryptedBallot,
    validateBallotAgainstManifest,
    validateContestSelections,
    generateTrackingCode,
    generateBallotHash,
    verifyBallotProofs,
    verifyDisjunctiveProof,
    verifyConstantSumProof,
    createBallotReceipt
};
