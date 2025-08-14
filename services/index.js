/**
 * ElectionGuard Services Module
 * 
 * Main entry point for all ElectionGuard services.
 * Provides the same functionality as the Python services directory.
 */

// Import all service modules
const setupGuardians = require('./setup_guardians');
const createEncryptedBallot = require('./create_encrypted_ballot');
const createEncryptedTally = require('./create_encrypted_tally');
const createPartialDecryption = require('./create_partial_decryption');
const createCompensatedDecryption = require('./create_compensated_decryption_shares');
const combineDecryptionShares = require('./combine_decryption_shares');

/**
 * Guardian Key Ceremony Services
 */
const GuardianServices = {
    /**
     * Setup guardians for key ceremony
     */
    setupGuardians: setupGuardians.setupGuardians,
    
    /**
     * Validate guardian configuration
     */
    validateGuardianConfig: setupGuardians.validateGuardianConfig,
    
    /**
     * Generate ceremony report
     */
    generateCeremonyReport: setupGuardians.generateCeremonyReport,
    
    /**
     * Export guardian data
     */
    exportGuardianData: setupGuardians.exportGuardianData
};

/**
 * Ballot Encryption Services
 */
const BallotServices = {
    /**
     * Create encrypted ballot from plaintext
     */
    createEncryptedBallot: createEncryptedBallot.createEncryptedBallot,
    
    /**
     * Validate ballot against manifest
     */
    validateBallotAgainstManifest: createEncryptedBallot.validateBallotAgainstManifest,
    
    /**
     * Generate tracking code for ballot
     */
    generateTrackingCode: createEncryptedBallot.generateTrackingCode,
    
    /**
     * Verify ballot proofs
     */
    verifyBallotProofs: createEncryptedBallot.verifyBallotProofs,
    
    /**
     * Create ballot receipt
     */
    createBallotReceipt: createEncryptedBallot.createBallotReceipt
};

/**
 * Tally Services
 */
const TallyServices = {
    /**
     * Create encrypted tally from submitted ballots
     */
    createEncryptedTally: createEncryptedTally.createEncryptedTally,
    
    /**
     * Validate ballots for tallying
     */
    validateBallotsForTallying: createEncryptedTally.validateBallotsForTallying,
    
    /**
     * Generate tally statistics
     */
    generateTallyStatistics: createEncryptedTally.generateTallyStatistics,
    
    /**
     * Export tally data
     */
    exportTallyData: createEncryptedTally.exportTallyData
};

/**
 * Decryption Services
 */
const DecryptionServices = {
    /**
     * Create partial decryption shares
     */
    createPartialDecryption: createPartialDecryption.createPartialDecryption,
    
    /**
     * Create compensated decryption for missing guardians
     */
    createCompensatedDecryption: createCompensatedDecryption.createCompensatedDecryption,
    
    /**
     * Combine decryption shares to produce plaintext tally
     */
    combineDecryptionShares: combineDecryptionShares.combineDecryptionShares,
    
    /**
     * Validate decryption shares
     */
    validateDecryptionShares: createPartialDecryption.validateDecryptionShares,
    
    /**
     * Export decryption results
     */
    exportDecryptionResults: combineDecryptionShares.exportDecryptionResults
};

/**
 * Comprehensive Election Services
 */
const ElectionServices = {
    
    /**
     * Complete election setup workflow
     */
    async setupElection(config) {
        try {
            const results = {
                success: true,
                steps: [],
                guardian_setup: null,
                manifest_validation: null,
                ready_for_voting: false
            };
            
            // Step 1: Setup guardians
            if (config.guardians) {
                const guardianResult = await GuardianServices.setupGuardians(
                    config.guardians.numberOfGuardians,
                    config.guardians.quorum,
                    config.guardians.ceremonySeed
                );
                
                results.guardian_setup = guardianResult;
                results.steps.push({
                    step: 'guardian_setup',
                    success: guardianResult.success,
                    timestamp: guardianResult.created_at
                });
                
                if (!guardianResult.success) {
                    results.success = false;
                    return results;
                }
            }
            
            // Step 2: Validate manifest
            if (config.manifest) {
                // Manifest validation would be implemented here
                results.steps.push({
                    step: 'manifest_validation',
                    success: true,
                    timestamp: new Date().toISOString()
                });
            }
            
            results.ready_for_voting = results.success;
            return results;
            
        } catch (error) {
            return {
                success: false,
                error: error.message,
                steps: []
            };
        }
    },
    
    /**
     * Complete voting workflow
     */
    async processVoting(ballots, manifest, context, guardians) {
        try {
            const results = {
                success: true,
                steps: [],
                encrypted_ballots: [],
                encrypted_tally: null,
                ready_for_decryption: false
            };
            
            // Step 1: Encrypt ballots
            for (const ballot of ballots) {
                const encryptionResult = await BallotServices.createEncryptedBallot(
                    ballot, manifest, context
                );
                
                results.encrypted_ballots.push(encryptionResult);
                results.steps.push({
                    step: 'ballot_encryption',
                    ballot_id: ballot.ballotId,
                    success: encryptionResult.success,
                    tracking_code: encryptionResult.tracking_code,
                    timestamp: encryptionResult.created_at
                });
                
                if (!encryptionResult.success) {
                    results.success = false;
                }
            }
            
            // Step 2: Create encrypted tally
            if (results.success && results.encrypted_ballots.length > 0) {
                const submittedBallots = results.encrypted_ballots
                    .filter(eb => eb.success)
                    .map(eb => ({
                        ballot: eb.ciphertext_ballot,
                        state: 'CAST'
                    }));
                
                const tallyResult = await TallyServices.createEncryptedTally(
                    submittedBallots, manifest, context
                );
                
                results.encrypted_tally = tallyResult;
                results.steps.push({
                    step: 'tally_creation',
                    success: tallyResult.success,
                    timestamp: tallyResult.created_at
                });
                
                results.ready_for_decryption = tallyResult.success;
            }
            
            return results;
            
        } catch (error) {
            return {
                success: false,
                error: error.message,
                steps: []
            };
        }
    },
    
    /**
     * Complete decryption workflow
     */
    async processDecryption(encryptedTally, guardians, context, missingGuardianIds = []) {
        try {
            const results = {
                success: true,
                steps: [],
                partial_decryptions: null,
                compensated_decryptions: null,
                plaintext_tally: null
            };
            
            // Step 1: Create partial decryptions
            const partialResult = await DecryptionServices.createPartialDecryption(
                encryptedTally, guardians, context
            );
            
            results.partial_decryptions = partialResult;
            results.steps.push({
                step: 'partial_decryption',
                success: partialResult.success,
                timestamp: partialResult.created_at
            });
            
            if (!partialResult.success) {
                results.success = false;
                return results;
            }
            
            // Step 2: Create compensated decryptions if needed
            let compensatedResult = null;
            if (missingGuardianIds.length > 0) {
                const availableGuardians = guardians.filter(g => 
                    !missingGuardianIds.includes(g.guardian_id || g.objectId)
                );
                
                compensatedResult = await DecryptionServices.createCompensatedDecryption(
                    encryptedTally, availableGuardians, missingGuardianIds, context
                );
                
                results.compensated_decryptions = compensatedResult;
                results.steps.push({
                    step: 'compensated_decryption',
                    success: compensatedResult.success,
                    timestamp: compensatedResult.created_at
                });
                
                if (!compensatedResult.success) {
                    results.success = false;
                    return results;
                }
            }
            
            // Step 3: Combine shares to produce plaintext tally
            const combineResult = await DecryptionServices.combineDecryptionShares(
                encryptedTally,
                partialResult.partial_decryptions,
                compensatedResult ? compensatedResult.compensated_decryptions : [],
                context
            );
            
            results.plaintext_tally = combineResult;
            results.steps.push({
                step: 'share_combination',
                success: combineResult.success,
                timestamp: combineResult.created_at
            });
            
            if (!combineResult.success) {
                results.success = false;
            }
            
            return results;
            
        } catch (error) {
            return {
                success: false,
                error: error.message,
                steps: []
            };
        }
    }
};

/**
 * Utility Services
 */
const UtilityServices = {
    /**
     * Validate election configuration
     */
    validateElectionConfig(config) {
        const errors = [];
        
        if (!config.guardians || !config.guardians.numberOfGuardians) {
            errors.push('Missing guardian configuration');
        }
        
        if (!config.manifest) {
            errors.push('Missing election manifest');
        }
        
        if (!config.context) {
            errors.push('Missing election context');
        }
        
        return {
            isValid: errors.length === 0,
            errors: errors
        };
    },
    
    /**
     * Generate election summary
     */
    generateElectionSummary(electionResults) {
        if (!electionResults.plaintext_tally || !electionResults.plaintext_tally.success) {
            return {
                status: 'INCOMPLETE',
                error: 'No valid plaintext tally available'
            };
        }
        
        const tally = electionResults.plaintext_tally.plaintext_tally;
        
        return {
            status: 'COMPLETED',
            total_votes: tally.contests ? 
                Object.values(tally.contests).reduce((total, contest) => {
                    if (contest.selections) {
                        return total + Object.values(contest.selections).reduce((contestTotal, selection) => {
                            return contestTotal + (selection.tally || 0);
                        }, 0);
                    }
                    return total;
                }, 0) : 0,
            contests_count: tally.contests ? Object.keys(tally.contests).length : 0,
            election_date: new Date().toISOString().split('T')[0],
            verification_hash: electionResults.plaintext_tally.tally_hash
        };
    }
};

// Export all services
module.exports = {
    GuardianServices,
    BallotServices,
    TallyServices,
    DecryptionServices,
    ElectionServices,
    UtilityServices,
    
    // Direct access to individual service functions
    setupGuardians: GuardianServices.setupGuardians,
    createEncryptedBallot: BallotServices.createEncryptedBallot,
    createEncryptedTally: TallyServices.createEncryptedTally,
    createPartialDecryption: DecryptionServices.createPartialDecryption,
    createCompensatedDecryption: DecryptionServices.createCompensatedDecryption,
    combineDecryptionShares: DecryptionServices.combineDecryptionShares
};
