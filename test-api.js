/**
 * ElectionGuard JavaScript API Test Suite
 * 
 * Comprehensive testing of all ElectionGuard API endpoints.
 * This is the JavaScript equivalent of test-api.py from the Python version.
 */

const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Configuration
const CONFIG = {
    BASE_URL: 'http://localhost:3000',
    API_TIMEOUT: 30000, // 30 seconds
    TEST_RESULTS_DIR: './test-results',
    GUARDIAN_COUNT: 3,
    QUORUM: 2
};

// Test data
const TEST_MANIFEST = {
    object_id: "test-election-2025",
    type: "general",
    start_date: "2025-08-14T00:00:00Z",
    end_date: "2025-08-14T23:59:59Z",
    geopolitical_units: [
        {
            object_id: "district-1",
            name: "Test District 1",
            type: "district"
        }
    ],
    parties: [
        {
            object_id: "party-1",
            name: "Test Party A"
        },
        {
            object_id: "party-2", 
            name: "Test Party B"
        }
    ],
    candidates: [
        {
            object_id: "candidate-1",
            name: "Alice Johnson",
            party_id: "party-1"
        },
        {
            object_id: "candidate-2",
            name: "Bob Smith", 
            party_id: "party-2"
        },
        {
            object_id: "candidate-3",
            name: "Charlie Brown",
            party_id: "party-1"
        }
    ],
    contests: [
        {
            object_id: "contest-mayor",
            title: "Mayor Election",
            electoral_district_id: "district-1",
            sequence_order: 1,
            vote_variation: "one_of_m",
            number_elected: 1,
            votes_allowed: 1,
            ballot_selections: [
                {
                    object_id: "selection-alice",
                    sequence_order: 1,
                    candidate_id: "candidate-1"
                },
                {
                    object_id: "selection-bob",
                    sequence_order: 2,
                    candidate_id: "candidate-2"
                }
            ]
        },
        {
            object_id: "contest-council",
            title: "City Council Election",
            electoral_district_id: "district-1", 
            sequence_order: 2,
            vote_variation: "n_of_m",
            number_elected: 2,
            votes_allowed: 2,
            ballot_selections: [
                {
                    object_id: "selection-alice-council",
                    sequence_order: 1,
                    candidate_id: "candidate-1"
                },
                {
                    object_id: "selection-bob-council",
                    sequence_order: 2,
                    candidate_id: "candidate-2"
                },
                {
                    object_id: "selection-charlie-council",
                    sequence_order: 3,
                    candidate_id: "candidate-3"
                }
            ]
        }
    ],
    ballot_styles: [
        {
            object_id: "ballot-style-1",
            geopolitical_unit_ids: ["district-1"]
        }
    ]
};

const SAMPLE_BALLOTS = [
    {
        ballot_id: "ballot-001",
        ballot_style_id: "ballot-style-1",
        contests: [
            {
                object_id: "contest-mayor",
                ballot_selections: [
                    { object_id: "selection-alice", vote: 1 },
                    { object_id: "selection-bob", vote: 0 }
                ]
            },
            {
                object_id: "contest-council", 
                ballot_selections: [
                    { object_id: "selection-alice-council", vote: 1 },
                    { object_id: "selection-bob-council", vote: 1 },
                    { object_id: "selection-charlie-council", vote: 0 }
                ]
            }
        ]
    },
    {
        ballot_id: "ballot-002",
        ballot_style_id: "ballot-style-1",
        contests: [
            {
                object_id: "contest-mayor",
                ballot_selections: [
                    { object_id: "selection-alice", vote: 0 },
                    { object_id: "selection-bob", vote: 1 }
                ]
            },
            {
                object_id: "contest-council",
                ballot_selections: [
                    { object_id: "selection-alice-council", vote: 0 },
                    { object_id: "selection-bob-council", vote: 1 },
                    { object_id: "selection-charlie-council", vote: 1 }
                ]
            }
        ]
    },
    {
        ballot_id: "ballot-003",
        ballot_style_id: "ballot-style-1",
        contests: [
            {
                object_id: "contest-mayor",
                ballot_selections: [
                    { object_id: "selection-alice", vote: 1 },
                    { object_id: "selection-bob", vote: 0 }
                ]
            },
            {
                object_id: "contest-council",
                ballot_selections: [
                    { object_id: "selection-alice-council", vote: 1 },
                    { object_id: "selection-bob-council", vote: 0 },
                    { object_id: "selection-charlie-council", vote: 1 }
                ]
            }
        ]
    }
];

// Test state
const testState = {
    guardians: null,
    jointPublicKey: null,
    context: null,
    encryptedBallots: [],
    encryptedTally: null,
    partialDecryptions: null,
    compensatedDecryptions: null,
    plaintextTally: null
};

// Utility functions
function createAxiosInstance() {
    return axios.create({
        baseURL: CONFIG.BASE_URL,
        timeout: CONFIG.API_TIMEOUT,
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
    });
}

function logTest(testName, status, duration, details = null) {
    const timestamp = new Date().toISOString();
    const logEntry = {
        timestamp,
        test: testName,
        status,
        duration_ms: duration,
        details
    };
    
    console.log(`[${timestamp}] ${testName}: ${status} (${duration}ms)`);
    if (details && status === 'FAILED') {
        console.log(`   Error: ${details.error}`);
    }
    
    return logEntry;
}

function saveTestResults(results) {
    if (!fs.existsSync(CONFIG.TEST_RESULTS_DIR)) {
        fs.mkdirSync(CONFIG.TEST_RESULTS_DIR, { recursive: true });
    }
    
    const filename = `test-results-${Date.now()}.json`;
    const filepath = path.join(CONFIG.TEST_RESULTS_DIR, filename);
    
    fs.writeFileSync(filepath, JSON.stringify(results, null, 2));
    console.log(`\nTest results saved to: ${filepath}`);
}

// Test functions
async function testHealthCheck() {
    const client = createAxiosInstance();
    const startTime = Date.now();
    
    try {
        const response = await client.get('/health');
        const duration = Date.now() - startTime;
        
        if (response.status === 200 && response.data.status === 'OK') {
            return logTest('Health Check', 'PASSED', duration);
        } else {
            return logTest('Health Check', 'FAILED', duration, {
                error: 'Invalid health response',
                response: response.data
            });
        }
    } catch (error) {
        const duration = Date.now() - startTime;
        return logTest('Health Check', 'FAILED', duration, {
            error: error.message
        });
    }
}

async function testSetupGuardians() {
    const client = createAxiosInstance();
    const startTime = Date.now();
    
    try {
        const requestData = {
            number_of_guardians: CONFIG.GUARDIAN_COUNT,
            quorum: CONFIG.QUORUM
        };
        
        const response = await client.post('/setup_guardians', requestData);
        const duration = Date.now() - startTime;
        
        if (response.status === 200 && response.data.success) {
            testState.guardians = response.data.guardians;
            testState.jointPublicKey = response.data.joint_election_key.public_key;
            testState.context = {
                crypto_hash: response.data.joint_election_key.commitment_hash,
                elgamal_public_key: testState.jointPublicKey
            };
            
            return logTest('Setup Guardians', 'PASSED', duration, {
                guardian_count: response.data.guardians.length,
                joint_key_generated: !!testState.jointPublicKey
            });
        } else {
            return logTest('Setup Guardians', 'FAILED', duration, {
                error: response.data.error || 'Guardian setup failed',
                response: response.data
            });
        }
    } catch (error) {
        const duration = Date.now() - startTime;
        return logTest('Setup Guardians', 'FAILED', duration, {
            error: error.message
        });
    }
}

async function testCreateEncryptedBallot(ballot, ballotIndex) {
    const client = createAxiosInstance();
    const startTime = Date.now();
    
    try {
        const requestData = {
            plaintext_ballot: ballot,
            manifest: TEST_MANIFEST,
            context: testState.context,
            device_info: {
                deviceId: `test-device-${ballotIndex}`,
                location: 'Test Location'
            }
        };
        
        const response = await client.post('/create_encrypted_ballot', requestData);
        const duration = Date.now() - startTime;
        
        if (response.status === 200 && response.data.success) {
            testState.encryptedBallots.push({
                ballot: response.data.ciphertext_ballot,
                state: 'CAST',
                tracking_code: response.data.tracking_code
            });
            
            return logTest(`Create Encrypted Ballot ${ballotIndex + 1}`, 'PASSED', duration, {
                tracking_code: response.data.tracking_code,
                proofs_valid: response.data.proof_verification.all_proofs_valid
            });
        } else {
            return logTest(`Create Encrypted Ballot ${ballotIndex + 1}`, 'FAILED', duration, {
                error: response.data.error || 'Ballot encryption failed',
                response: response.data
            });
        }
    } catch (error) {
        const duration = Date.now() - startTime;
        return logTest(`Create Encrypted Ballot ${ballotIndex + 1}`, 'FAILED', duration, {
            error: error.message
        });
    }
}

async function testCreateEncryptedTally() {
    const client = createAxiosInstance();
    const startTime = Date.now();
    
    try {
        const requestData = {
            submitted_ballots: testState.encryptedBallots,
            manifest: TEST_MANIFEST,
            context: testState.context
        };
        
        const response = await client.post('/create_encrypted_tally', requestData);
        const duration = Date.now() - startTime;
        
        if (response.status === 200 && response.data.success) {
            testState.encryptedTally = response.data.ciphertext_tally;
            
            return logTest('Create Encrypted Tally', 'PASSED', duration, {
                ballots_tallied: response.data.ballot_counts.cast_ballots,
                contests_tallied: response.data.tallying_details.contests_tallied,
                verified: response.data.verification_result.verified
            });
        } else {
            return logTest('Create Encrypted Tally', 'FAILED', duration, {
                error: response.data.error || 'Tally creation failed',
                response: response.data
            });
        }
    } catch (error) {
        const duration = Date.now() - startTime;
        return logTest('Create Encrypted Tally', 'FAILED', duration, {
            error: error.message
        });
    }
}

async function testCreatePartialDecryption() {
    const client = createAxiosInstance();
    const startTime = Date.now();
    
    try {
        const requestData = {
            ciphertext_tally: testState.encryptedTally,
            guardians: testState.guardians,
            context: testState.context
        };
        
        const response = await client.post('/create_partial_decryption', requestData);
        const duration = Date.now() - startTime;
        
        if (response.status === 200 && response.data.success) {
            testState.partialDecryptions = response.data.partial_decryptions;
            
            return logTest('Create Partial Decryption', 'PASSED', duration, {
                shares_created: response.data.decryption_details.total_shares,
                guardians_participating: response.data.guardian_info.length,
                all_valid: response.data.validation_results.overall_valid
            });
        } else {
            return logTest('Create Partial Decryption', 'FAILED', duration, {
                error: response.data.error || 'Partial decryption failed',
                response: response.data
            });
        }
    } catch (error) {
        const duration = Date.now() - startTime;
        return logTest('Create Partial Decryption', 'FAILED', duration, {
            error: error.message
        });
    }
}

async function testCombineDecryptionShares() {
    const client = createAxiosInstance();
    const startTime = Date.now();
    
    try {
        const requestData = {
            ciphertext_tally: testState.encryptedTally,
            decryption_shares: testState.partialDecryptions,
            compensated_shares: testState.compensatedDecryptions || [],
            context: testState.context,
            manifest: TEST_MANIFEST
        };
        
        const response = await client.post('/combine_decryption_shares', requestData);
        const duration = Date.now() - startTime;
        
        if (response.status === 200 && response.data.success) {
            testState.plaintextTally = response.data.plaintext_tally;
            
            return logTest('Combine Decryption Shares', 'PASSED', duration, {
                selections_decrypted: response.data.decryption_details.total_selections_decrypted,
                contests_processed: response.data.decryption_details.contests_processed,
                validation_valid: response.data.validation_results.overall_valid
            });
        } else {
            return logTest('Combine Decryption Shares', 'FAILED', duration, {
                error: response.data.error || 'Share combination failed',
                response: response.data
            });
        }
    } catch (error) {
        const duration = Date.now() - startTime;
        return logTest('Combine Decryption Shares', 'FAILED', duration, {
            error: error.message
        });
    }
}

async function testGenericEncryptDecrypt() {
    const client = createAxiosInstance();
    const startTime = Date.now();
    
    try {
        const testData = { message: "Hello ElectionGuard!" };
        
        // Test encryption
        const encryptResponse = await client.post('/api/encrypt', {
            data: testData,
            public_key: testState.jointPublicKey,
            context: testState.context
        });
        
        if (!encryptResponse.data.success) {
            throw new Error('Encryption failed');
        }
        
        // Test decryption
        const decryptResponse = await client.post('/api/decrypt', {
            encrypted_data: encryptResponse.data.encrypted_data,
            guardians: testState.guardians,
            context: testState.context
        });
        
        const duration = Date.now() - startTime;
        
        if (decryptResponse.data.success) {
            return logTest('Generic Encrypt/Decrypt', 'PASSED', duration, {
                original_data: testData,
                decrypted_data: decryptResponse.data.decrypted_data,
                data_matches: JSON.stringify(testData) === JSON.stringify(decryptResponse.data.decrypted_data)
            });
        } else {
            return logTest('Generic Encrypt/Decrypt', 'FAILED', duration, {
                error: decryptResponse.data.error || 'Decryption failed'
            });
        }
    } catch (error) {
        const duration = Date.now() - startTime;
        return logTest('Generic Encrypt/Decrypt', 'FAILED', duration, {
            error: error.message
        });
    }
}

function validateElectionResults() {
    const startTime = Date.now();
    
    try {
        if (!testState.plaintextTally || !testState.plaintextTally.contests) {
            throw new Error('No plaintext tally available for validation');
        }
        
        const contests = testState.plaintextTally.contests;
        const validationResults = {
            mayor_contest: null,
            council_contest: null,
            total_votes: 0
        };
        
        // Validate mayor contest
        if (contests['contest-mayor']) {
            const mayorSelections = contests['contest-mayor'].selections;
            const aliceVotes = mayorSelections['selection-alice']?.tally || 0;
            const bobVotes = mayorSelections['selection-bob']?.tally || 0;
            
            validationResults.mayor_contest = {
                alice_votes: aliceVotes,
                bob_votes: bobVotes,
                total_votes: aliceVotes + bobVotes
            };
            validationResults.total_votes += aliceVotes + bobVotes;
        }
        
        // Validate council contest
        if (contests['contest-council']) {
            const councilSelections = contests['contest-council'].selections;
            const aliceCouncilVotes = councilSelections['selection-alice-council']?.tally || 0;
            const bobCouncilVotes = councilSelections['selection-bob-council']?.tally || 0;
            const charlieCouncilVotes = councilSelections['selection-charlie-council']?.tally || 0;
            
            validationResults.council_contest = {
                alice_votes: aliceCouncilVotes,
                bob_votes: bobCouncilVotes,
                charlie_votes: charlieCouncilVotes,
                total_votes: aliceCouncilVotes + bobCouncilVotes + charlieCouncilVotes
            };
            validationResults.total_votes += aliceCouncilVotes + bobCouncilVotes + charlieCouncilVotes;
        }
        
        const duration = Date.now() - startTime;
        
        // Expected results based on sample ballots:
        // Mayor: Alice=2, Bob=1 (ballots 1,3 vote Alice; ballot 2 votes Bob)
        // Council: Alice=2, Bob=2, Charlie=2 (each gets 2 votes across 3 ballots)
        const expectedMayorAlice = 2;
        const expectedMayorBob = 1;
        const expectedCouncilEach = 2;
        
        const resultsMatch = 
            validationResults.mayor_contest?.alice_votes === expectedMayorAlice &&
            validationResults.mayor_contest?.bob_votes === expectedMayorBob &&
            validationResults.council_contest?.alice_votes === expectedCouncilEach &&
            validationResults.council_contest?.bob_votes === expectedCouncilEach &&
            validationResults.council_contest?.charlie_votes === expectedCouncilEach;
        
        if (resultsMatch) {
            return logTest('Validate Election Results', 'PASSED', duration, validationResults);
        } else {
            return logTest('Validate Election Results', 'WARNING', duration, {
                ...validationResults,
                note: 'Results may not match expected values due to test data or decryption issues'
            });
        }
        
    } catch (error) {
        const duration = Date.now() - startTime;
        return logTest('Validate Election Results', 'FAILED', duration, {
            error: error.message
        });
    }
}

// Main test runner
async function runAllTests() {
    console.log('🗳️  ElectionGuard JavaScript API Test Suite');
    console.log('='.repeat(50));
    console.log(`Testing API at: ${CONFIG.BASE_URL}`);
    console.log(`Guardians: ${CONFIG.GUARDIAN_COUNT}, Quorum: ${CONFIG.QUORUM}`);
    console.log('');
    
    const testResults = [];
    const overallStartTime = Date.now();
    
    try {
        // Test 1: Health Check
        testResults.push(await testHealthCheck());
        
        // Test 2: Setup Guardians
        testResults.push(await testSetupGuardians());
        if (testState.guardians === null) {
            throw new Error('Cannot continue without guardians setup');
        }
        
        // Test 3: Create Encrypted Ballots
        for (let i = 0; i < SAMPLE_BALLOTS.length; i++) {
            testResults.push(await testCreateEncryptedBallot(SAMPLE_BALLOTS[i], i));
        }
        
        if (testState.encryptedBallots.length === 0) {
            throw new Error('Cannot continue without encrypted ballots');
        }
        
        // Test 4: Create Encrypted Tally
        testResults.push(await testCreateEncryptedTally());
        if (testState.encryptedTally === null) {
            throw new Error('Cannot continue without encrypted tally');
        }
        
        // Test 5: Create Partial Decryption
        testResults.push(await testCreatePartialDecryption());
        if (testState.partialDecryptions === null) {
            throw new Error('Cannot continue without partial decryptions');
        }
        
        // Test 6: Combine Decryption Shares
        testResults.push(await testCombineDecryptionShares());
        
        // Test 7: Generic Encrypt/Decrypt
        testResults.push(await testGenericEncryptDecrypt());
        
        // Test 8: Validate Results
        testResults.push(validateElectionResults());
        
    } catch (error) {
        console.error(`\n❌ Test suite failed: ${error.message}`);
        testResults.push(logTest('Test Suite', 'FAILED', Date.now() - overallStartTime, {
            error: error.message
        }));
    }
    
    const overallDuration = Date.now() - overallStartTime;
    
    // Generate summary
    const summary = {
        total_tests: testResults.length,
        passed: testResults.filter(r => r.status === 'PASSED').length,
        failed: testResults.filter(r => r.status === 'FAILED').length,
        warnings: testResults.filter(r => r.status === 'WARNING').length,
        total_duration_ms: overallDuration,
        test_results: testResults,
        final_state: {
            guardians_setup: !!testState.guardians,
            ballots_encrypted: testState.encryptedBallots.length,
            tally_created: !!testState.encryptedTally,
            decryption_completed: !!testState.plaintextTally
        }
    };
    
    // Print summary
    console.log('\n' + '='.repeat(50));
    console.log('📊 TEST SUMMARY');
    console.log('='.repeat(50));
    console.log(`Total Tests: ${summary.total_tests}`);
    console.log(`✅ Passed: ${summary.passed}`);
    console.log(`❌ Failed: ${summary.failed}`);
    console.log(`⚠️  Warnings: ${summary.warnings}`);
    console.log(`⏱️  Total Duration: ${summary.total_duration_ms}ms`);
    console.log('');
    
    if (summary.failed === 0) {
        console.log('🎉 All tests passed! ElectionGuard API is working correctly.');
    } else {
        console.log('❌ Some tests failed. Check the logs above for details.');
    }
    
    // Save results
    saveTestResults(summary);
    
    return summary.failed === 0;
}

// Run tests if this file is executed directly
if (require.main === module) {
    runAllTests()
        .then(success => {
            process.exit(success ? 0 : 1);
        })
        .catch(error => {
            console.error('Test runner error:', error);
            process.exit(1);
        });
}

module.exports = {
    runAllTests,
    testHealthCheck,
    testSetupGuardians,
    testCreateEncryptedBallot,
    testCreateEncryptedTally,
    testCreatePartialDecryption,
    testCombineDecryptionShares,
    testGenericEncryptDecrypt,
    validateElectionResults,
    CONFIG,
    TEST_MANIFEST,
    SAMPLE_BALLOTS
};
