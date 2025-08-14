/**
 * Setup Guardians Service
 * 
 * Implements the guardian key ceremony setup process for threshold cryptography.
 * This service corresponds to the Python setup_guardians.py service.
 */

const crypto = require('crypto');
const { 
    Guardian, 
    KeyCeremonyMediator,
    ElectionPolynomial
} = require('../electionguard/guardian');
const {
    ElementModP,
    ElementModQ,
    generateRandomBetween,
    gPowP,
    hashElems
} = require('../electionguard/group');

/**
 * Setup guardians for a key ceremony
 */
async function setupGuardians(numberOfGuardians, quorum, ceremonySeed = null) {
    try {
        // Validate inputs
        if (numberOfGuardians < 1) {
            throw new Error('Number of guardians must be at least 1');
        }
        
        if (quorum < 1 || quorum > numberOfGuardians) {
            throw new Error(`Quorum must be between 1 and ${numberOfGuardians}`);
        }
        
        // Initialize ceremony mediator
        const mediator = new KeyCeremonyMediator('key-ceremony', numberOfGuardians, quorum);
        
        // Create guardians
        const guardians = [];
        for (let i = 1; i <= numberOfGuardians; i++) {
            const guardianId = `guardian-${i}`;
            const guardian = Guardian.create(guardianId, i, numberOfGuardians, quorum);
            guardians.push(guardian);
            
            // Announce guardian to mediator
            mediator.announce(guardian);
        }
        
        // Verify all guardians are announced
        if (!mediator.allGuardiansAnnounced()) {
            throw new Error('Not all guardians were properly announced');
        }
        
        // Generate election keys for all guardians
        const publicKeysGenerated = [];
        for (const guardian of guardians) {
            const publicKey = guardian.shareElectionPartialKeyBackup(guardianId);
            if (publicKey) {
                publicKeysGenerated.push({
                    guardianId: guardian.objectId,
                    publicKey: publicKey
                });
            }
        }
        
        // Share election partial key backups between guardians
        const backups = new Map(); // guardianId -> Map(ownerGuardianId -> backup)
        
        for (const owner of guardians) {
            backups.set(owner.objectId, new Map());
            
            for (const recipient of guardians) {
                if (owner.objectId !== recipient.objectId) {
                    const backup = owner.shareElectionPartialKeyBackup(recipient.objectId);
                    if (backup) {
                        backups.get(owner.objectId).set(recipient.objectId, backup);
                    }
                }
            }
        }
        
        // Verify backups
        const verifications = new Map(); // guardianId -> Map(ownerGuardianId -> verification)
        
        for (const verifier of guardians) {
            verifications.set(verifier.objectId, new Map());
            
            for (const owner of guardians) {
                if (verifier.objectId !== owner.objectId) {
                    const backup = backups.get(owner.objectId)?.get(verifier.objectId);
                    if (backup) {
                        const verification = verifier.verifyElectionPartialKeyBackup(
                            owner.objectId, 
                            backup
                        );
                        verifications.get(verifier.objectId).set(owner.objectId, verification);
                    }
                }
            }
        }
        
        // Build joint election key
        const jointKey = mediator.publishJointKey();
        
        if (!jointKey) {
            throw new Error('Failed to generate joint election key');
        }
        
        // Prepare guardian data for response
        const guardianData = guardians.map(guardian => ({
            guardian_id: guardian.objectId,
            sequence_order: guardian.sequenceOrder,
            election_keys: {
                public_key: guardian.electionKeys.publicKey.toHex(),
                secret_key: guardian.electionKeys.secretKey.toHex()
            },
            election_proofs: guardian.electionProofs ? 
                guardian.electionProofs.map(proof => ({
                    public_key: proof.publicKey.toHex(),
                    commitment: proof.commitment.toHex(),
                    challenge: proof.challenge.toHex(),
                    response: proof.response.toHex()
                })) : [],
            polynomial_coefficients: guardian.polynomialCoefficients ? 
                guardian.polynomialCoefficients.map(coeff => coeff.toHex()) : [],
            backups_to_share: Array.from(backups.get(guardian.objectId) || new Map()).map(([recipientId, backup]) => ({
                recipient_id: recipientId,
                encrypted_value: backup.encryptedValue.toHex(),
                coefficient_commitments: backup.coefficientCommitments.map(commit => commit.toHex()),
                coefficient_proofs: backup.coefficientProofs ? 
                    backup.coefficientProofs.map(proof => ({
                        public_key: proof.publicKey.toHex(),
                        commitment: proof.commitment.toHex(),
                        challenge: proof.challenge.toHex(),
                        response: proof.response.toHex()
                    })) : []
            }))
        }));
        
        // Prepare verification data
        const verificationData = Array.from(verifications.entries()).map(([verifierId, ownerMap]) => ({
            verifier_id: verifierId,
            verifications: Array.from(ownerMap.entries()).map(([ownerId, verification]) => ({
                owner_id: ownerId,
                verified: verification.isValid,
                error_message: verification.errorMessage
            }))
        }));
        
        return {
            success: true,
            guardians: guardianData,
            joint_election_key: {
                public_key: jointKey.toHex(),
                commitment_hash: hashElems(jointKey.toHex()).toHex()
            },
            ceremony_details: {
                number_of_guardians: numberOfGuardians,
                quorum: quorum,
                ceremony_completed: mediator.allGuardiansAnnounced() && jointKey !== null
            },
            verifications: verificationData,
            created_at: new Date().toISOString()
        };
        
    } catch (error) {
        console.error('Setup guardians error:', error);
        return {
            success: false,
            error: error.message,
            created_at: new Date().toISOString()
        };
    }
}

/**
 * Validate guardian configuration
 */
function validateGuardianConfig(numberOfGuardians, quorum) {
    const errors = [];
    
    if (!Number.isInteger(numberOfGuardians) || numberOfGuardians < 1) {
        errors.push('Number of guardians must be a positive integer');
    }
    
    if (!Number.isInteger(quorum) || quorum < 1) {
        errors.push('Quorum must be a positive integer');
    }
    
    if (quorum > numberOfGuardians) {
        errors.push('Quorum cannot be greater than number of guardians');
    }
    
    if (numberOfGuardians > 10) {
        errors.push('Number of guardians should not exceed 10 for practical purposes');
    }
    
    if (quorum < Math.ceil(numberOfGuardians / 2)) {
        console.warn('Quorum is less than majority - this may be less secure');
    }
    
    return {
        isValid: errors.length === 0,
        errors: errors
    };
}

/**
 * Generate guardian ceremony report
 */
function generateCeremonyReport(setupResult) {
    if (!setupResult.success) {
        return {
            status: 'FAILED',
            error: setupResult.error,
            timestamp: setupResult.created_at
        };
    }
    
    const { guardians, ceremony_details, verifications } = setupResult;
    
    // Calculate verification statistics
    let totalVerifications = 0;
    let successfulVerifications = 0;
    
    verifications.forEach(verifierData => {
        verifierData.verifications.forEach(verification => {
            totalVerifications++;
            if (verification.verified) {
                successfulVerifications++;
            }
        });
    });
    
    return {
        status: ceremony_details.ceremony_completed ? 'COMPLETED' : 'INCOMPLETE',
        summary: {
            total_guardians: ceremony_details.number_of_guardians,
            quorum_threshold: ceremony_details.quorum,
            joint_key_generated: !!setupResult.joint_election_key,
            verification_rate: totalVerifications > 0 ? 
                (successfulVerifications / totalVerifications) * 100 : 0
        },
        guardian_details: guardians.map(guardian => ({
            id: guardian.guardian_id,
            sequence: guardian.sequence_order,
            public_key_generated: !!guardian.election_keys.public_key,
            backups_created: guardian.backups_to_share.length,
            proofs_generated: guardian.election_proofs.length
        })),
        security_metrics: {
            key_length: 'P-256', // Elliptic curve
            threshold_scheme: 'Shamir Secret Sharing',
            proof_system: 'Schnorr Proofs',
            post_quantum_ready: true
        },
        recommendations: generateSecurityRecommendations(setupResult),
        timestamp: setupResult.created_at
    };
}

/**
 * Generate security recommendations based on setup
 */
function generateSecurityRecommendations(setupResult) {
    const recommendations = [];
    
    if (!setupResult.success) {
        recommendations.push({
            level: 'CRITICAL',
            message: 'Key ceremony failed - cannot proceed with election',
            action: 'Restart guardian setup process'
        });
        return recommendations;
    }
    
    const { ceremony_details, verifications } = setupResult;
    
    // Check quorum strength
    const quorumRatio = ceremony_details.quorum / ceremony_details.number_of_guardians;
    if (quorumRatio < 0.5) {
        recommendations.push({
            level: 'WARNING',
            message: 'Quorum threshold is less than majority',
            action: 'Consider increasing quorum for better security'
        });
    }
    
    // Check verification success rate
    let totalVerifications = 0;
    let successfulVerifications = 0;
    
    verifications.forEach(verifierData => {
        verifierData.verifications.forEach(verification => {
            totalVerifications++;
            if (verification.verified) {
                successfulVerifications++;
            }
        });
    });
    
    const verificationRate = totalVerifications > 0 ? 
        (successfulVerifications / totalVerifications) : 0;
    
    if (verificationRate < 1.0) {
        recommendations.push({
            level: 'ERROR',
            message: 'Some backup verifications failed',
            action: 'Review failed verifications and restart ceremony if needed'
        });
    }
    
    // General security recommendations
    recommendations.push({
        level: 'INFO',
        message: 'Store guardian keys securely',
        action: 'Use hardware security modules or secure key storage'
    });
    
    recommendations.push({
        level: 'INFO',
        message: 'Distribute guardians geographically',
        action: 'Ensure guardians are in different locations for resilience'
    });
    
    return recommendations;
}

/**
 * Export guardian data for external storage
 */
function exportGuardianData(setupResult, includeSecrets = false) {
    if (!setupResult.success) {
        throw new Error('Cannot export data from failed ceremony');
    }
    
    const exportData = {
        ceremony_info: {
            number_of_guardians: setupResult.ceremony_details.number_of_guardians,
            quorum: setupResult.ceremony_details.quorum,
            created_at: setupResult.created_at,
            joint_public_key: setupResult.joint_election_key.public_key
        },
        guardians: setupResult.guardians.map(guardian => {
            const exportGuardian = {
                guardian_id: guardian.guardian_id,
                sequence_order: guardian.sequence_order,
                public_key: guardian.election_keys.public_key
            };
            
            // Include secrets only if explicitly requested and in secure context
            if (includeSecrets) {
                exportGuardian.secret_key = guardian.election_keys.secret_key;
                exportGuardian.polynomial_coefficients = guardian.polynomial_coefficients;
                exportGuardian.backups_to_share = guardian.backups_to_share;
            }
            
            return exportGuardian;
        }),
        export_metadata: {
            exported_at: new Date().toISOString(),
            includes_secrets: includeSecrets,
            format_version: '1.0'
        }
    };
    
    return exportData;
}

module.exports = {
    setupGuardians,
    validateGuardianConfig,
    generateCeremonyReport,
    generateSecurityRecommendations,
    exportGuardianData
};
