/**
 * ElectionGuard Encryption
 * 
 * Implements ballot encryption with zero-knowledge proofs
 * and homomorphic properties for secure tallying.
 */

const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { 
    ElementModP, 
    ElementModQ, 
    randomQ, 
    gPowP, 
    hashElems 
} = require('./group');
const { 
    ElGamalPublicKey, 
    ElGamalCiphertext 
} = require('./elgamal');
const {
    PlaintextBallot,
    CiphertextBallot,
    PlaintextBallotContest,
    CiphertextBallotContest,
    PlaintextBallotSelection,
    CiphertextBallotSelection
} = require('./ballot');

/**
 * Encryption Device
 */
class EncryptionDevice {
    constructor(deviceId, sessionId = null, launchCode = null, location = null) {
        this.deviceId = deviceId;
        this.sessionId = sessionId || uuidv4();
        this.launchCode = launchCode || this.generateLaunchCode();
        this.location = location;
        this.timestamp = Date.now();
    }
    
    generateLaunchCode() {
        return crypto.randomBytes(16).toString('hex').toUpperCase();
    }
    
    toJSON() {
        return {
            device_id: this.deviceId,
            session_id: this.sessionId,
            launch_code: this.launchCode,
            location: this.location,
            timestamp: this.timestamp
        };
    }
    
    static fromJSON(json) {
        return new EncryptionDevice(
            json.device_id || json.deviceId,
            json.session_id || json.sessionId,
            json.launch_code || json.launchCode,
            json.location
        );
    }
}

/**
 * Disjunctive Chaum-Pedersen Proof
 * Proves that an encrypted vote is either 0 or 1
 */
class DisjunctiveChaumPedersenProof {
    constructor(proof0, proof1, challenge) {
        this.proof0 = proof0; // Proof for vote = 0
        this.proof1 = proof1; // Proof for vote = 1  
        this.challenge = challenge instanceof ElementModQ ? challenge : new ElementModQ(challenge);
    }
    
    /**
     * Generate proof that ciphertext encrypts either 0 or 1
     */
    static generate(plaintext, nonce, publicKey, ciphertext, hashHeader = null) {
        const vote = typeof plaintext === 'number' ? plaintext : (plaintext.element ? plaintext.element.toNumber() : 0);
        
        if (vote === 0) {
            return DisjunctiveChaumPedersenProof.generateForZero(nonce, publicKey, ciphertext, hashHeader);
        } else if (vote === 1) {
            return DisjunctiveChaumPedersenProof.generateForOne(nonce, publicKey, ciphertext, hashHeader);
        } else {
            throw new Error('Vote must be 0 or 1 for disjunctive proof');
        }
    }
    
    /**
     * Generate proof when vote = 0
     */
    static generateForZero(nonce, publicKey, ciphertext, hashHeader = null) {
        // Real proof for 0
        const u0 = randomQ();
        const a0 = gPowP(u0);
        const b0 = publicKey.key.pow(u0);
        
        // Simulated proof for 1
        const c1 = randomQ();
        const v1 = randomQ();
        const a1 = gPowP(v1).multiply(ciphertext.alpha.pow(c1.negate()));
        const g = gPowP(new ElementModQ(1));
        const b1 = publicKey.key.pow(v1).multiply(ciphertext.beta.multiply(g.pow(c1.negate())).pow(c1.negate()));
        
        // Challenge
        const elements = [publicKey.key, ciphertext.alpha, ciphertext.beta, a0, b0, a1, b1];
        if (hashHeader) elements.unshift(hashHeader);
        const c = hashElems(...elements);
        
        const c0 = c.add(c1.negate());
        const v0 = u0.add(c0.multiply(nonce));
        
        return new DisjunctiveChaumPedersenProof(
            { commitment: a0, response: v0, challenge: c0 },
            { commitment: a1, response: v1, challenge: c1 },
            c
        );
    }
    
    /**
     * Generate proof when vote = 1
     */
    static generateForOne(nonce, publicKey, ciphertext, hashHeader = null) {
        // Simulated proof for 0
        const c0 = randomQ();
        const v0 = randomQ();
        const a0 = gPowP(v0).multiply(ciphertext.alpha.pow(c0.negate()));
        const b0 = publicKey.key.pow(v0).multiply(ciphertext.beta.pow(c0.negate()));
        
        // Real proof for 1
        const u1 = randomQ();
        const a1 = gPowP(u1);
        const b1 = publicKey.key.pow(u1);
        
        // Challenge
        const elements = [publicKey.key, ciphertext.alpha, ciphertext.beta, a0, b0, a1, b1];
        if (hashHeader) elements.unshift(hashHeader);
        const c = hashElems(...elements);
        
        const c1 = c.add(c0.negate());
        const g = gPowP(new ElementModQ(1));
        const v1 = u1.add(c1.multiply(nonce));
        
        return new DisjunctiveChaumPedersenProof(
            { commitment: a0, response: v0, challenge: c0 },
            { commitment: a1, response: v1, challenge: c1 },
            c
        );
    }
    
    /**
     * Verify the disjunctive proof
     */
    verify(publicKey, ciphertext, hashHeader = null) {
        try {
            const { proof0, proof1, challenge } = this;
            
            // Verify challenge sum
            const computedChallenge = proof0.challenge.add(proof1.challenge);
            if (!computedChallenge.equals(challenge)) {
                return false;
            }
            
            // Verify proof 0
            const gv0 = gPowP(proof0.response);
            const ac0 = ciphertext.alpha.pow(proof0.challenge);
            const a0_check = proof0.commitment.multiply(ac0);
            if (!gv0.equals(a0_check)) return false;
            
            const kv0 = publicKey.key.pow(proof0.response);
            const bc0 = ciphertext.beta.pow(proof0.challenge);
            const b0_check = proof0.commitment.multiply(bc0);
            if (!kv0.equals(b0_check)) return false;
            
            // Verify proof 1
            const gv1 = gPowP(proof1.response);
            const ac1 = ciphertext.alpha.pow(proof1.challenge);
            const a1_check = proof1.commitment.multiply(ac1);
            if (!gv1.equals(a1_check)) return false;
            
            const kv1 = publicKey.key.pow(proof1.response);
            const g = gPowP(new ElementModQ(1));
            const bc1 = ciphertext.beta.multiply(g).pow(proof1.challenge);
            const b1_check = proof1.commitment.multiply(bc1);
            if (!kv1.equals(b1_check)) return false;
            
            // Verify challenge computation
            const elements = [publicKey.key, ciphertext.alpha, ciphertext.beta, 
                            proof0.commitment, proof0.commitment, proof1.commitment, proof1.commitment];
            if (hashHeader) elements.unshift(hashHeader);
            const expectedChallenge = hashElems(...elements);
            
            return challenge.equals(expectedChallenge);
        } catch (error) {
            console.error('Proof verification error:', error);
            return false;
        }
    }
    
    toJSON() {
        return {
            proof_zero: {
                commitment: this.proof0.commitment.toJSON(),
                response: this.proof0.response.toJSON(),
                challenge: this.proof0.challenge.toJSON()
            },
            proof_one: {
                commitment: this.proof1.commitment.toJSON(),
                response: this.proof1.response.toJSON(),
                challenge: this.proof1.challenge.toJSON()
            },
            challenge: this.challenge.toJSON()
        };
    }
    
    static fromJSON(json) {
        return new DisjunctiveChaumPedersenProof(
            {
                commitment: new ElementModP(json.proof_zero.commitment),
                response: new ElementModQ(json.proof_zero.response),
                challenge: new ElementModQ(json.proof_zero.challenge)
            },
            {
                commitment: new ElementModP(json.proof_one.commitment),
                response: new ElementModQ(json.proof_one.response),
                challenge: new ElementModQ(json.proof_one.challenge)
            },
            json.challenge
        );
    }
}

/**
 * Constant Chaum-Pedersen Proof
 * Proves that the sum of selections equals a constant (usually the vote limit)
 */
class ConstantChaumPedersenProof {
    constructor(commitment, response, challenge, constant) {
        this.commitment = commitment instanceof ElementModP ? commitment : new ElementModP(commitment);
        this.response = response instanceof ElementModQ ? response : new ElementModQ(response);
        this.challenge = challenge instanceof ElementModQ ? challenge : new ElementModQ(challenge);
        this.constant = constant;
    }
    
    static generate(selections, nonces, constant, publicKey, hashHeader = null) {
        // Sum the selections and nonces
        let totalMessage = new ElementModQ(0);
        let totalNonce = new ElementModQ(0);
        
        for (let i = 0; i < selections.length; i++) {
            const vote = typeof selections[i] === 'number' ? selections[i] : selections[i].vote;
            totalMessage = totalMessage.add(new ElementModQ(vote));
            totalNonce = totalNonce.add(nonces[i]);
        }
        
        // Generate commitment
        const u = randomQ();
        const commitment = gPowP(u);
        
        // Generate challenge
        const elements = [publicKey.key, commitment];
        if (hashHeader) elements.unshift(hashHeader);
        const challenge = hashElems(...elements);
        
        // Generate response
        const constantDiff = totalMessage.add(new ElementModQ(-constant));
        const response = u.add(challenge.multiply(constantDiff));
        
        return new ConstantChaumPedersenProof(commitment, response, challenge, constant);
    }
    
    verify(sumCiphertext, publicKey, hashHeader = null) {
        try {
            // Recompute commitment
            const gv = gPowP(this.response);
            const constantElement = gPowP(new ElementModQ(this.constant));
            const adjustedBeta = sumCiphertext.beta.multiply(constantElement.pow(new ElementModQ(-1)));
            const ac = adjustedBeta.pow(this.challenge);
            const expectedCommitment = gv.multiply(ac.pow(new ElementModQ(-1)));
            
            if (!this.commitment.equals(expectedCommitment)) {
                return false;
            }
            
            // Verify challenge
            const elements = [publicKey.key, this.commitment];
            if (hashHeader) elements.unshift(hashHeader);
            const expectedChallenge = hashElems(...elements);
            
            return this.challenge.equals(expectedChallenge);
        } catch (error) {
            console.error('Constant proof verification error:', error);
            return false;
        }
    }
    
    toJSON() {
        return {
            commitment: this.commitment.toJSON(),
            response: this.response.toJSON(),
            challenge: this.challenge.toJSON(),
            constant: this.constant
        };
    }
    
    static fromJSON(json) {
        return new ConstantChaumPedersenProof(
            json.commitment,
            json.response,
            json.challenge,
            json.constant
        );
    }
}

/**
 * Encryption Mediator
 */
class EncryptionMediator {
    constructor(manifest, context, encryptionDevice) {
        this.manifest = manifest;
        this.context = context;
        this.encryptionDevice = encryptionDevice;
    }
    
    /**
     * Encrypt a plaintext ballot
     */
    encrypt(plaintextBallot) {
        if (!(plaintextBallot instanceof PlaintextBallot)) {
            throw new Error('Must provide PlaintextBallot');
        }
        
        const ciphertextBallot = new CiphertextBallot(
            plaintextBallot.ballotId,
            plaintextBallot.ballotStyleId,
            this.manifest.manifestHash ? this.manifest.manifestHash.toHex() : null
        );
        
        // Encrypt each contest
        for (const plaintextContest of plaintextBallot.contests) {
            const ciphertextContest = this.encryptContest(plaintextContest, ciphertextBallot.ballotId);
            ciphertextBallot.addContest(ciphertextContest);
        }
        
        // Generate ballot code and crypto hash
        ciphertextBallot.generateBallotCode();
        ciphertextBallot.computeCryptoHash();
        
        return ciphertextBallot;
    }
    
    /**
     * Encrypt a single contest
     */
    encryptContest(plaintextContest, ballotId) {
        const contestManifest = this.manifest.getContest ? 
            this.manifest.getContest(plaintextContest.objectId) : null;
        
        const ciphertextContest = new CiphertextBallotContest(plaintextContest.objectId);
        const selectionNonces = [];
        
        // Encrypt each selection
        for (const plaintextSelection of plaintextContest.ballotSelections) {
            const nonce = randomQ();
            selectionNonces.push(nonce);
            
            const ciphertextSelection = this.encryptSelection(
                plaintextSelection, 
                nonce, 
                ballotId,
                plaintextContest.objectId
            );
            ciphertextContest.addSelection(ciphertextSelection);
        }
        
        // Generate contest proof (sum equals vote limit)
        if (contestManifest) {
            const voteLimit = contestManifest.numberElected || 1;
            const hashHeader = `${ballotId}-${plaintextContest.objectId}`;
            
            try {
                const proof = ConstantChaumPedersenProof.generate(
                    plaintextContest.ballotSelections,
                    selectionNonces,
                    voteLimit,
                    this.context.jointPublicKey,
                    hashHeader
                );
                ciphertextContest.proof = proof;
            } catch (error) {
                console.warn('Failed to generate contest proof:', error.message);
            }
        }
        
        // Compute accumulation
        ciphertextContest.computeAccumulation();
        
        return ciphertextContest;
    }
    
    /**
     * Encrypt a single selection
     */
    encryptSelection(plaintextSelection, nonce, ballotId, contestId) {
        const publicKey = this.context.jointPublicKey instanceof ElGamalPublicKey ?
            this.context.jointPublicKey : new ElGamalPublicKey(this.context.jointPublicKey);
        
        const vote = new ElementModQ(plaintextSelection.vote);
        const ciphertext = publicKey.encrypt(vote, nonce);
        
        // Generate disjunctive proof (vote is 0 or 1)
        let proof = null;
        try {
            const hashHeader = `${ballotId}-${contestId}-${plaintextSelection.objectId}`;
            proof = DisjunctiveChaumPedersenProof.generate(
                plaintextSelection.vote,
                nonce,
                publicKey,
                ciphertext,
                hashHeader
            );
        } catch (error) {
            console.warn('Failed to generate selection proof:', error.message);
        }
        
        return new CiphertextBallotSelection(
            plaintextSelection.objectId,
            ciphertext,
            proof,
            plaintextSelection.isPlaceholderSelection
        );
    }
    
    /**
     * Verify an encrypted ballot
     */
    verify(ciphertextBallot) {
        try {
            // Verify basic structure
            if (!ciphertextBallot.isValid()) {
                return false;
            }
            
            // Verify each contest
            for (const contest of ciphertextBallot.contests) {
                if (!this.verifyContest(contest, ciphertextBallot.ballotId)) {
                    return false;
                }
            }
            
            return true;
        } catch (error) {
            console.error('Ballot verification error:', error);
            return false;
        }
    }
    
    /**
     * Verify an encrypted contest
     */
    verifyContest(ciphertextContest, ballotId) {
        try {
            const publicKey = this.context.jointPublicKey instanceof ElGamalPublicKey ?
                this.context.jointPublicKey : new ElGamalPublicKey(this.context.jointPublicKey);
            
            // Verify each selection
            for (const selection of ciphertextContest.ballotSelections) {
                if (!this.verifySelection(selection, ballotId, ciphertextContest.objectId, publicKey)) {
                    return false;
                }
            }
            
            // Verify contest proof if present
            if (ciphertextContest.proof && ciphertextContest.ciphertextAccumulation) {
                const hashHeader = `${ballotId}-${ciphertextContest.objectId}`;
                if (!ciphertextContest.proof.verify(ciphertextContest.ciphertextAccumulation, publicKey, hashHeader)) {
                    return false;
                }
            }
            
            return true;
        } catch (error) {
            console.error('Contest verification error:', error);
            return false;
        }
    }
    
    /**
     * Verify an encrypted selection
     */
    verifySelection(ciphertextSelection, ballotId, contestId, publicKey) {
        try {
            // Verify ciphertext is valid
            if (!ciphertextSelection.ciphertext.isValid()) {
                return false;
            }
            
            // Verify proof if present
            if (ciphertextSelection.proof) {
                const hashHeader = `${ballotId}-${contestId}-${ciphertextSelection.objectId}`;
                if (!ciphertextSelection.proof.verify(publicKey, ciphertextSelection.ciphertext, hashHeader)) {
                    return false;
                }
            }
            
            return true;
        } catch (error) {
            console.error('Selection verification error:', error);
            return false;
        }
    }
    
    toJSON() {
        return {
            manifest: this.manifest.toJSON ? this.manifest.toJSON() : this.manifest,
            context: this.context.toJSON ? this.context.toJSON() : this.context,
            encryption_device: this.encryptionDevice.toJSON()
        };
    }
    
    static fromJSON(json, manifest, context) {
        const device = EncryptionDevice.fromJSON(json.encryption_device || json.encryptionDevice);
        return new EncryptionMediator(manifest || json.manifest, context || json.context, device);
    }
}

/**
 * Helper function to encrypt a ballot with given parameters
 */
function encryptBallot(plaintextBallot, manifest, jointPublicKey, commitmentHash, deviceInfo = null) {
    const device = deviceInfo ? EncryptionDevice.fromJSON(deviceInfo) : 
        new EncryptionDevice(uuidv4(), uuidv4());
    
    const context = {
        jointPublicKey: jointPublicKey,
        commitmentHash: commitmentHash,
        manifestHash: manifest.computeHash ? manifest.computeHash() : null
    };
    
    const mediator = new EncryptionMediator(manifest, context, device);
    return mediator.encrypt(plaintextBallot);
}

module.exports = {
    EncryptionDevice,
    DisjunctiveChaumPedersenProof,
    ConstantChaumPedersenProof,
    EncryptionMediator,
    encryptBallot
};
