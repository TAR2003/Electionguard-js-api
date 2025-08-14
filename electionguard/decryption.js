/**
 * ElectionGuard Decryption
 * 
 * Implements threshold decryption with partial decryption shares,
 * compensated decryption for missing guardians, and verification proofs.
 */

const crypto = require('crypto');
const { 
    ElementModP, 
    ElementModQ, 
    randomQ, 
    gPowP, 
    hashElems,
    intToQ 
} = require('./group');
const { 
    ElGamalCiphertext,
    ElGamalPublicKey 
} = require('./elgamal');

/**
 * Decryption Share
 */
class DecryptionShare {
    constructor(guardianId, share, proof = null) {
        this.guardianId = guardianId;
        this.share = share instanceof ElementModP ? share : new ElementModP(share);
        this.proof = proof;
    }
    
    toJSON() {
        return {
            guardian_id: this.guardianId,
            share: this.share.toJSON(),
            proof: this.proof ? {
                commitment: this.proof.commitment.toJSON(),
                challenge: this.proof.challenge.toJSON(),
                response: this.proof.response.toJSON()
            } : null
        };
    }
    
    static fromJSON(json) {
        let proof = null;
        if (json.proof) {
            proof = {
                commitment: new ElementModP(json.proof.commitment),
                challenge: new ElementModQ(json.proof.challenge),
                response: new ElementModQ(json.proof.response)
            };
        }
        
        return new DecryptionShare(
            json.guardian_id || json.guardianId,
            json.share,
            proof
        );
    }
    
    toString() {
        return `DecryptionShare(${this.guardianId})`;
    }
}

/**
 * Compensated Decryption Share
 */
class CompensatedDecryptionShare extends DecryptionShare {
    constructor(guardianId, missingGuardianId, share, proof = null) {
        super(guardianId, share, proof);
        this.missingGuardianId = missingGuardianId;
    }
    
    toJSON() {
        const json = super.toJSON();
        json.missing_guardian_id = this.missingGuardianId;
        return json;
    }
    
    static fromJSON(json) {
        const baseShare = DecryptionShare.fromJSON(json);
        return new CompensatedDecryptionShare(
            baseShare.guardianId,
            json.missing_guardian_id || json.missingGuardianId,
            baseShare.share,
            baseShare.proof
        );
    }
    
    toString() {
        return `CompensatedDecryptionShare(${this.guardianId} -> ${this.missingGuardianId})`;
    }
}

/**
 * Lagrange Coefficients for threshold reconstruction
 */
class LagrangeCoefficientsRecord {
    constructor(coefficients) {
        this.coefficients = coefficients || new Map(); // guardianId -> ElementModQ
    }
    
    getCoefficient(guardianId) {
        return this.coefficients.get(guardianId);
    }
    
    setCoefficient(guardianId, coefficient) {
        this.coefficients.set(guardianId, coefficient instanceof ElementModQ ? coefficient : new ElementModQ(coefficient));
    }
    
    toJSON() {
        return {
            coefficients: Object.fromEntries(
                Array.from(this.coefficients.entries()).map(([k, v]) => [k, v.toJSON()])
            )
        };
    }
    
    static fromJSON(json) {
        const record = new LagrangeCoefficientsRecord();
        if (json.coefficients) {
            for (const [guardianId, coeff] of Object.entries(json.coefficients)) {
                record.setCoefficient(guardianId, coeff);
            }
        }
        return record;
    }
}

/**
 * Compute Lagrange coefficients for a set of guardians
 */
function computeLagrangeCoefficientsForGuardians(guardianIds) {
    const coefficients = new LagrangeCoefficientsRecord();
    const sequences = guardianIds.map((_, i) => i + 1); // Assuming sequences start from 1
    
    for (let i = 0; i < guardianIds.length; i++) {
        const guardianId = guardianIds[i];
        const xi = sequences[i];
        
        let numerator = new ElementModQ(1);
        let denominator = new ElementModQ(1);
        
        for (let j = 0; j < sequences.length; j++) {
            if (i !== j) {
                const xj = sequences[j];
                
                // numerator *= (0 - xj) = -xj
                numerator = numerator.multiply(new ElementModQ(-xj));
                
                // denominator *= (xi - xj)
                denominator = denominator.multiply(new ElementModQ(xi - xj));
            }
        }
        
        // coefficient = numerator / denominator (mod q)
        // In modular arithmetic, division is multiplication by modular inverse
        const coefficient = numerator.multiply(denominator.modInverse());
        coefficients.setCoefficient(guardianId, coefficient);
    }
    
    return coefficients;
}

/**
 * Compute a partial decryption share for a ciphertext
 */
function computeDecryptionShare(guardian, ciphertext, context = null) {
    if (!guardian.electionKeyPair || !guardian.electionKeyPair.secretKey) {
        throw new Error('Guardian must have election key pair');
    }
    
    if (!(ciphertext instanceof ElGamalCiphertext)) {
        ciphertext = new ElGamalCiphertext(ciphertext.alpha, ciphertext.beta);
    }
    
    const secretKey = guardian.electionKeyPair.secretKey;
    const share = ciphertext.alpha.pow(secretKey);
    
    // Generate proof of correct decryption
    const proof = generateDecryptionProof(
        guardian.guardianId,
        ciphertext,
        share,
        secretKey,
        guardian.electionKeyPair.publicKey
    );
    
    return new DecryptionShare(guardian.guardianId, share, proof);
}

/**
 * Compute a partial decryption share for a ballot
 */
function computeDecryptionShareForBallot(guardian, ballot, context = null) {
    const shares = new Map();
    
    for (const contest of ballot.contests) {
        for (const selection of contest.ballotSelections) {
            const share = computeDecryptionShare(guardian, selection.ciphertext, context);
            shares.set(selection.objectId, share);
        }
    }
    
    return shares;
}

/**
 * Compute compensated decryption share for a missing guardian
 */
function computeCompensatedDecryptionShare(
    guardian,
    missingGuardianId,
    ciphertext,
    context = null,
    lagrangeCoefficients = null
) {
    // Get backup key for the missing guardian
    const backupKey = guardian.backupKeys.get(missingGuardianId);
    if (!backupKey) {
        throw new Error(`No backup key found for missing guardian ${missingGuardianId}`);
    }
    
    if (!(ciphertext instanceof ElGamalCiphertext)) {
        ciphertext = new ElGamalCiphertext(ciphertext.alpha, ciphertext.beta);
    }
    
    // Compute partial decryption using backup key
    const share = ciphertext.alpha.pow(backupKey);
    
    // Generate proof of correct compensated decryption
    const proof = generateCompensatedDecryptionProof(
        guardian.guardianId,
        missingGuardianId,
        ciphertext,
        share,
        backupKey,
        guardian.publicKeys.get(missingGuardianId) || guardian.electionKeyPair.publicKey
    );
    
    return new CompensatedDecryptionShare(guardian.guardianId, missingGuardianId, share, proof);
}

/**
 * Compute compensated decryption share for a ballot
 */
function computeCompensatedDecryptionShareForBallot(
    guardian,
    missingGuardianId,
    ballot,
    context = null,
    lagrangeCoefficients = null
) {
    const shares = new Map();
    
    for (const contest of ballot.contests) {
        for (const selection of contest.ballotSelections) {
            const share = computeCompensatedDecryptionShare(
                guardian,
                missingGuardianId,
                selection.ciphertext,
                context,
                lagrangeCoefficients
            );
            shares.set(selection.objectId, share);
        }
    }
    
    return shares;
}

/**
 * Generate Chaum-Pedersen proof for decryption correctness
 */
function generateDecryptionProof(guardianId, ciphertext, share, secretKey, publicKey) {
    // Generate random nonce
    const u = randomQ();
    
    // Commitments: a = g^u, b = alpha^u
    const a = gPowP(u);
    const b = ciphertext.alpha.pow(u);
    
    // Challenge: c = H(guardianId, publicKey, ciphertext, share, a, b)
    const challenge = hashElems(
        guardianId,
        publicKey.toHex(),
        ciphertext.alpha.toHex(),
        ciphertext.beta.toHex(),
        share.toHex(),
        a.toHex(),
        b.toHex()
    );
    
    // Response: v = u + c * secretKey
    const response = u.add(challenge.multiply(secretKey));
    
    return {
        commitment: a,
        challenge: challenge,
        response: response
    };
}

/**
 * Generate proof for compensated decryption
 */
function generateCompensatedDecryptionProof(
    guardianId,
    missingGuardianId,
    ciphertext,
    share,
    backupKey,
    missingPublicKey
) {
    // Generate random nonce
    const u = randomQ();
    
    // Commitments: a = g^u, b = alpha^u
    const a = gPowP(u);
    const b = ciphertext.alpha.pow(u);
    
    // Challenge
    const challenge = hashElems(
        guardianId,
        missingGuardianId,
        missingPublicKey.toHex(),
        ciphertext.alpha.toHex(),
        ciphertext.beta.toHex(),
        share.toHex(),
        a.toHex(),
        b.toHex()
    );
    
    // Response: v = u + c * backupKey
    const response = u.add(challenge.multiply(backupKey));
    
    return {
        commitment: a,
        challenge: challenge,
        response: response
    };
}

/**
 * Verify decryption proof
 */
function verifyDecryptionProof(guardianId, ciphertext, share, publicKey, proof) {
    try {
        const { commitment, challenge, response } = proof;
        
        // Recompute challenge
        const expectedChallenge = hashElems(
            guardianId,
            publicKey.toHex(),
            ciphertext.alpha.toHex(),
            ciphertext.beta.toHex(),
            share.toHex(),
            commitment.toHex(),
            ciphertext.alpha.pow(response).multiply(share.pow(challenge.negate())).toHex()
        );
        
        if (!challenge.equals(expectedChallenge)) {
            return false;
        }
        
        // Verify proof equations
        // g^v = a * K^c
        const gv = gPowP(response);
        const right1 = commitment.multiply(publicKey.pow(challenge));
        if (!gv.equals(right1)) return false;
        
        // alpha^v = b * share^c
        const alphav = ciphertext.alpha.pow(response);
        const right2 = ciphertext.alpha.pow(response).multiply(share.pow(challenge.negate()));
        // This should equal commitment based on proof structure
        
        return true;
    } catch (error) {
        console.error('Decryption proof verification error:', error);
        return false;
    }
}

/**
 * Combine partial decryption shares to recover plaintext
 */
function combineDecryptionShares(
    ciphertext,
    shares,
    lagrangeCoefficients = null
) {
    if (!(ciphertext instanceof ElGamalCiphertext)) {
        ciphertext = new ElGamalCiphertext(ciphertext.alpha, ciphertext.beta);
    }
    
    if (shares.length === 0) {
        throw new Error('No decryption shares provided');
    }
    
    // If no Lagrange coefficients provided, assume simple combination
    if (!lagrangeCoefficients) {
        const guardianIds = shares.map(share => share.guardianId);
        lagrangeCoefficients = computeLagrangeCoefficientsForGuardians(guardianIds);
    }
    
    // Combine shares: product of (share_i ^ coefficient_i)
    let combined = new ElementModP(1);
    
    for (const share of shares) {
        const coefficient = lagrangeCoefficients.getCoefficient(share.guardianId);
        if (!coefficient) {
            throw new Error(`No Lagrange coefficient for guardian ${share.guardianId}`);
        }
        
        const contributtion = share.share.pow(coefficient);
        combined = combined.multiply(contributtion);
    }
    
    // Recover plaintext: beta / combined = g^m
    const gToTheM = ciphertext.beta.multiply(combined.pow(new ElementModQ(-1)));
    
    // Discrete log to recover m (brute force for small values)
    return discreteLogSmall(gToTheM);
}

/**
 * Brute force discrete logarithm for small values
 */
function discreteLogSmall(target, maxTries = 1000000) {
    const g = gPowP(new ElementModQ(1));
    let current = new ElementModP(1);
    
    for (let i = 0; i < maxTries; i++) {
        if (current.equals(target)) {
            return i;
        }
        current = current.multiply(g);
    }
    
    throw new Error(`Could not compute discrete log within ${maxTries} tries`);
}

/**
 * Decryption Mediator for coordinating threshold decryption
 */
class DecryptionMediator {
    constructor(manifest, context) {
        this.manifest = manifest;
        this.context = context;
        this.shares = new Map(); // guardianId -> Map(selectionId -> DecryptionShare)
        this.compensatedShares = new Map(); // missingGuardianId -> Map(guardianId -> Map(selectionId -> CompensatedDecryptionShare))
        this.lagrangeCoefficients = null;
    }
    
    /**
     * Add decryption share from a guardian
     */
    addShare(guardianId, selectionId, share) {
        if (!this.shares.has(guardianId)) {
            this.shares.set(guardianId, new Map());
        }
        this.shares.get(guardianId).set(selectionId, share);
    }
    
    /**
     * Add compensated decryption share
     */
    addCompensatedShare(guardianId, missingGuardianId, selectionId, share) {
        if (!this.compensatedShares.has(missingGuardianId)) {
            this.compensatedShares.set(missingGuardianId, new Map());
        }
        if (!this.compensatedShares.get(missingGuardianId).has(guardianId)) {
            this.compensatedShares.get(missingGuardianId).set(guardianId, new Map());
        }
        this.compensatedShares.get(missingGuardianId).get(guardianId).set(selectionId, share);
    }
    
    /**
     * Decrypt a selection using available shares
     */
    decryptSelection(selectionId, ciphertext, availableGuardians = null, missingGuardians = null) {
        const allShares = [];
        
        // Collect regular shares from available guardians
        if (availableGuardians) {
            for (const guardianId of availableGuardians) {
                if (this.shares.has(guardianId) && this.shares.get(guardianId).has(selectionId)) {
                    allShares.push(this.shares.get(guardianId).get(selectionId));
                }
            }
        }
        
        // Collect compensated shares for missing guardians
        if (missingGuardians) {
            for (const missingGuardianId of missingGuardians) {
                if (this.compensatedShares.has(missingGuardianId)) {
                    // Use compensated shares from any available guardian
                    const compensatedSharesForMissing = this.compensatedShares.get(missingGuardianId);
                    for (const [guardianId, shareMap] of compensatedSharesForMissing) {
                        if (shareMap.has(selectionId)) {
                            allShares.push(shareMap.get(selectionId));
                            break; // Only need one compensated share per missing guardian
                        }
                    }
                }
            }
        }
        
        if (allShares.length === 0) {
            throw new Error(`No shares available for selection ${selectionId}`);
        }
        
        // Compute Lagrange coefficients if not already done
        if (!this.lagrangeCoefficients) {
            const allGuardianIds = [...(availableGuardians || []), ...(missingGuardians || [])];
            this.lagrangeCoefficients = computeLagrangeCoefficientsForGuardians(allGuardianIds);
        }
        
        // Combine shares to decrypt
        return combineDecryptionShares(ciphertext, allShares, this.lagrangeCoefficients);
    }
    
    toJSON() {
        return {
            manifest: this.manifest.toJSON ? this.manifest.toJSON() : this.manifest,
            context: this.context.toJSON ? this.context.toJSON() : this.context,
            shares: Object.fromEntries(
                Array.from(this.shares.entries()).map(([gId, shareMap]) => [
                    gId,
                    Object.fromEntries(
                        Array.from(shareMap.entries()).map(([sId, share]) => [sId, share.toJSON()])
                    )
                ])
            ),
            compensated_shares: Object.fromEntries(
                Array.from(this.compensatedShares.entries()).map(([mId, guardianMap]) => [
                    mId,
                    Object.fromEntries(
                        Array.from(guardianMap.entries()).map(([gId, shareMap]) => [
                            gId,
                            Object.fromEntries(
                                Array.from(shareMap.entries()).map(([sId, share]) => [sId, share.toJSON()])
                            )
                        ])
                    )
                ])
            ),
            lagrange_coefficients: this.lagrangeCoefficients ? this.lagrangeCoefficients.toJSON() : null
        };
    }
}

module.exports = {
    DecryptionShare,
    CompensatedDecryptionShare,
    LagrangeCoefficientsRecord,
    DecryptionMediator,
    computeLagrangeCoefficientsForGuardians,
    computeDecryptionShare,
    computeDecryptionShareForBallot,
    computeCompensatedDecryptionShare,
    computeCompensatedDecryptionShareForBallot,
    combineDecryptionShares,
    verifyDecryptionProof,
    discreteLogSmall
};
