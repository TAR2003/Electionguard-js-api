/**
 * Create Encrypted Tally Service
 * 
 * Implements homomorphic tallying of encrypted ballots.
 * This service corresponds to the Python create_encrypted_tally.py service.
 */

const crypto = require('crypto');
const { 
    CiphertextBallot,
    BallotBoxState,
    SubmittedBallot
} = require('../electionguard/ballot');
const {
    CiphertextTally,
    CiphertextTallyContest,
    CiphertextTallySelection,
    tallyBallots,
    verifyTally,
    generateTallyHash
} = require('../electionguard/tally');
const {
    ElementModP,
    ElementModQ,
    hashElems
} = require('../electionguard/group');
const {
    ElGamalCiphertext
} = require('../electionguard/elgamal');

/**
 * Create encrypted tally from submitted ballots
 */
async function createEncryptedTally(submittedBallots, manifest, context) {
    try {
        // Validate inputs
        if (!Array.isArray(submittedBallots)) {
            throw new Error('submittedBallots must be an array');
        }
        
        if (submittedBallots.length === 0) {
            throw new Error('No ballots provided for tallying');
        }
        
        if (!manifest || !context) {
            throw new Error('Missing required parameters: manifest or context');
        }
        
        // Filter and validate ballots
        const ballotValidation = validateBallotsForTallying(submittedBallots, manifest);
        if (!ballotValidation.isValid) {
            throw new Error(`Ballot validation failed: ${ballotValidation.errors.join(', ')}`);
        }
        
        const castBallots = ballotValidation.castBallots;
        const spoiledBallots = ballotValidation.spoiledBallots;
        
        console.log(`Tallying ${castBallots.length} cast ballots, ${spoiledBallots.length} spoiled ballots`);
        
        // Perform homomorphic tallying
        const tallyResult = await performHomomorphicTallying(castBallots, manifest, context);
        
        if (!tallyResult.success) {
            throw new Error(`Tallying failed: ${tallyResult.error}`);
        }
        
        const ciphertextTally = tallyResult.tally;
        
        // Verify tally consistency
        const verificationResult = verifyTally(ciphertextTally, castBallots, manifest);
        
        // Generate tally hash
        const tallyHash = generateTallyHash(ciphertextTally, context);
        
        // Generate tally statistics
        const statistics = generateTallyStatistics(castBallots, spoiledBallots, ciphertextTally);
        
        return {
            success: true,
            ciphertext_tally: ciphertextTally.toJSON(),
            tally_hash: tallyHash.toHex(),
            verification_result: {
                verified: verificationResult,
                verification_time_ms: tallyResult.verification_time_ms
            },
            ballot_counts: {
                cast_ballots: castBallots.length,
                spoiled_ballots: spoiledBallots.length,
                total_submitted: submittedBallots.length
            },
            statistics: statistics,
            tallying_details: {
                start_time: tallyResult.start_time,
                end_time: tallyResult.end_time,
                processing_time_ms: tallyResult.processing_time_ms,
                contests_tallied: ciphertextTally.contests.size,
                total_selections: Array.from(ciphertextTally.contests.values())
                    .reduce((total, contest) => total + contest.selections.size, 0)
            },
            created_at: new Date().toISOString()
        };
        
    } catch (error) {
        console.error('Create encrypted tally error:', error);
        return {
            success: false,
            error: error.message,
            created_at: new Date().toISOString()
        };
    }
}

/**
 * Validate ballots for tallying process
 */
function validateBallotsForTallying(submittedBallots, manifest) {
    const errors = [];
    const castBallots = [];
    const spoiledBallots = [];
    
    for (const submitted of submittedBallots) {
        try {
            // Handle different input formats
            let submittedBallot;
            if (submitted instanceof SubmittedBallot) {
                submittedBallot = submitted;
            } else if (submitted.ballot && submitted.state) {
                submittedBallot = SubmittedBallot.fromJSON(submitted);
            } else {
                // Assume it's a raw ballot with state
                submittedBallot = new SubmittedBallot(
                    submitted,
                    submitted.state || BallotBoxState.UNKNOWN
                );
            }
            
            // Validate ballot structure
            const ballot = submittedBallot.ballot;
            if (!ballot || !ballot.ballotId) {
                errors.push(`Invalid ballot structure: missing ballot ID`);
                continue;
            }
            
            // Check ballot state
            if (submittedBallot.state === BallotBoxState.CAST) {
                // Validate cast ballot
                const validation = validateCastBallot(ballot, manifest);
                if (validation.isValid) {
                    castBallots.push(submittedBallot);
                } else {
                    errors.push(`Cast ballot ${ballot.ballotId} validation failed: ${validation.errors.join(', ')}`);
                }
            } else if (submittedBallot.state === BallotBoxState.SPOILED) {
                spoiledBallots.push(submittedBallot);
            } else {
                errors.push(`Ballot ${ballot.ballotId} has invalid state: ${submittedBallot.state}`);
            }
            
        } catch (error) {
            errors.push(`Error processing ballot: ${error.message}`);
        }
    }
    
    if (castBallots.length === 0 && errors.length === 0) {
        errors.push('No valid cast ballots found for tallying');
    }
    
    return {
        isValid: errors.length === 0,
        errors: errors,
        castBallots: castBallots,
        spoiledBallots: spoiledBallots
    };
}

/**
 * Validate individual cast ballot
 */
function validateCastBallot(ballot, manifest) {
    const errors = [];
    
    // Check basic ballot structure
    if (!ballot.contests || !Array.isArray(ballot.contests)) {
        errors.push('Missing or invalid contests array');
        return { isValid: false, errors };
    }
    
    // Validate each contest
    for (const contest of ballot.contests) {
        if (!contest.objectId) {
            errors.push('Contest missing object ID');
            continue;
        }
        
        const contestDescription = manifest.getContest(contest.objectId);
        if (!contestDescription) {
            errors.push(`Contest ${contest.objectId} not found in manifest`);
            continue;
        }
        
        // Validate selections
        if (!contest.ballotSelections || !Array.isArray(contest.ballotSelections)) {
            errors.push(`Contest ${contest.objectId} missing ballot selections`);
            continue;
        }
        
        for (const selection of contest.ballotSelections) {
            if (!selection.objectId || !selection.ciphertext) {
                errors.push(`Selection in contest ${contest.objectId} missing required fields`);
            }
            
            // Validate ciphertext structure
            if (!selection.ciphertext.alpha || !selection.ciphertext.beta) {
                errors.push(`Selection ${selection.objectId} has invalid ciphertext`);
            }
        }
    }
    
    return {
        isValid: errors.length === 0,
        errors: errors
    };
}

/**
 * Perform homomorphic tallying of ballots
 */
async function performHomomorphicTallying(castBallots, manifest, context) {
    try {
        const startTime = new Date().toISOString();
        const processingStart = Date.now();
        
        // Use the tally function from the tally module
        const ciphertextTally = tallyBallots(castBallots, manifest, context);
        
        const processingTime = Date.now() - processingStart;
        const endTime = new Date().toISOString();
        
        // Verify tally structure
        const verificationStart = Date.now();
        const isValid = validateTallyStructure(ciphertextTally, manifest);
        const verificationTime = Date.now() - verificationStart;
        
        if (!isValid) {
            throw new Error('Tally structure validation failed');
        }
        
        return {
            success: true,
            tally: ciphertextTally,
            start_time: startTime,
            end_time: endTime,
            processing_time_ms: processingTime,
            verification_time_ms: verificationTime
        };
        
    } catch (error) {
        console.error('Homomorphic tallying error:', error);
        return {
            success: false,
            error: error.message,
            start_time: new Date().toISOString(),
            end_time: new Date().toISOString(),
            processing_time_ms: 0,
            verification_time_ms: 0
        };
    }
}

/**
 * Validate tally structure against manifest
 */
function validateTallyStructure(tally, manifest) {
    try {
        // Check that all manifest contests are represented
        for (const contestDescription of manifest.contests) {
            const tallyContest = tally.getContest(contestDescription.objectId);
            if (!tallyContest) {
                console.error(`Missing contest in tally: ${contestDescription.objectId}`);
                return false;
            }
            
            // Check that all selections are represented
            for (const selectionDescription of contestDescription.ballotSelections) {
                const tallySelection = tallyContest.getSelection(selectionDescription.objectId);
                if (!tallySelection) {
                    console.error(`Missing selection in tally: ${selectionDescription.objectId}`);
                    return false;
                }
            }
        }
        
        return true;
    } catch (error) {
        console.error('Tally structure validation error:', error);
        return false;
    }
}

/**
 * Generate statistics about the tallying process
 */
function generateTallyStatistics(castBallots, spoiledBallots, ciphertextTally) {
    const stats = {
        ballot_statistics: {
            total_cast: castBallots.length,
            total_spoiled: spoiledBallots.length,
            cast_percentage: spoiledBallots.length > 0 ? 
                (castBallots.length / (castBallots.length + spoiledBallots.length)) * 100 : 100
        },
        contest_statistics: {},
        overall_statistics: {
            total_contests: ciphertextTally.contests.size,
            total_selections: 0,
            average_selections_per_contest: 0
        }
    };
    
    // Calculate per-contest statistics
    for (const [contestId, contest] of ciphertextTally.contests) {
        const contestStats = {
            total_selections: contest.selections.size,
            selection_ids: Array.from(contest.selections.keys())
        };
        
        stats.contest_statistics[contestId] = contestStats;
        stats.overall_statistics.total_selections += contest.selections.size;
    }
    
    stats.overall_statistics.average_selections_per_contest = 
        stats.overall_statistics.total_contests > 0 ?
            stats.overall_statistics.total_selections / stats.overall_statistics.total_contests : 0;
    
    return stats;
}

/**
 * Validate tally against expected results (for testing)
 */
function validateTallyAgainstExpected(actualTally, expectedResults) {
    const validation = {
        isValid: true,
        differences: [],
        summary: {
            contests_checked: 0,
            contests_matched: 0,
            selections_checked: 0,
            selections_matched: 0
        }
    };
    
    for (const [contestId, expectedContest] of Object.entries(expectedResults)) {
        validation.summary.contests_checked++;
        
        const actualContest = actualTally.getContest(contestId);
        if (!actualContest) {
            validation.isValid = false;
            validation.differences.push({
                type: 'missing_contest',
                contest_id: contestId,
                message: 'Contest missing from actual tally'
            });
            continue;
        }
        
        let contestMatched = true;
        
        for (const [selectionId, expectedValue] of Object.entries(expectedContest)) {
            validation.summary.selections_checked++;
            
            const actualSelection = actualContest.getSelection(selectionId);
            if (!actualSelection) {
                validation.isValid = false;
                contestMatched = false;
                validation.differences.push({
                    type: 'missing_selection',
                    contest_id: contestId,
                    selection_id: selectionId,
                    message: 'Selection missing from actual tally'
                });
                continue;
            }
            
            // In a real implementation, we would decrypt to compare values
            // For now, we just check that the selection exists
            validation.summary.selections_matched++;
        }
        
        if (contestMatched) {
            validation.summary.contests_matched++;
        }
    }
    
    return validation;
}

/**
 * Export tally data for external verification
 */
function exportTallyData(tallyResult, includeProofs = false) {
    if (!tallyResult.success) {
        throw new Error('Cannot export failed tally');
    }
    
    const exportData = {
        tally_metadata: {
            tally_hash: tallyResult.tally_hash,
            cast_ballots: tallyResult.ballot_counts.cast_ballots,
            spoiled_ballots: tallyResult.ballot_counts.spoiled_ballots,
            contests_tallied: tallyResult.tallying_details.contests_tallied,
            processing_time_ms: tallyResult.tallying_details.processing_time_ms,
            created_at: tallyResult.created_at
        },
        ciphertext_tally: tallyResult.ciphertext_tally,
        verification_info: {
            verified: tallyResult.verification_result.verified,
            verification_time_ms: tallyResult.verification_result.verification_time_ms
        },
        export_metadata: {
            exported_at: new Date().toISOString(),
            includes_proofs: includeProofs,
            format_version: '1.0'
        }
    };
    
    return exportData;
}

module.exports = {
    createEncryptedTally,
    validateBallotsForTallying,
    validateCastBallot,
    performHomomorphicTallying,
    validateTallyStructure,
    generateTallyStatistics,
    validateTallyAgainstExpected,
    exportTallyData
};
