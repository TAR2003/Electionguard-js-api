/**
 * ElectionGuard Guardian and Key Ceremony
 * 
 * Implements guardian key generation, polynomial sharing,
 * and key ceremony coordination for threshold cryptography.
 */

const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { 
    ElementModP, 
    ElementModQ, 
    randomQ, 
    gPowP, 
    hashElems,
    Constants 
} = require('./group');
const { 
    ElGamalKeyPair, 
    ElGamalPublicKey, 
    ElGamalSecretKey 
} = require('./elgamal');

/**
 * Election Polynomial for Secret Sharing
 */
class ElectionPolynomial {
    constructor(coefficients) {
        if (!Array.isArray(coefficients) || coefficients.length === 0) {
            throw new Error('Coefficients must be non-empty array');
        }
        
        this.coefficients = coefficients.map(coeff => {
            if (coeff instanceof ElementModQ) return coeff;
            if (coeff && coeff.coefficient) return new ElementModQ(coeff.coefficient);
            return new ElementModQ(coeff);
        });
    }
    
    /**
     * Generate random polynomial of given degree
     */
    static generate(degree, secret = null) {
        const coefficients = [];
        
        // First coefficient is the secret (constant term)
        coefficients.push(secret || randomQ());
        
        // Generate random coefficients for higher degree terms
        for (let i = 1; i <= degree; i++) {
            coefficients.push(randomQ());
        }
        
        return new ElectionPolynomial(coefficients);
    }
    
    /**
     * Evaluate polynomial at given point
     */
    evaluate(x) {
        if (typeof x === 'number') {
            x = new ElementModQ(x);
        } else if (!(x instanceof ElementModQ)) {
            x = new ElementModQ(x);
        }
        
        let result = new ElementModQ(0);
        let xPower = new ElementModQ(1);
        
        for (const coeff of this.coefficients) {
            result = result.add(coeff.multiply(xPower));
            xPower = xPower.multiply(x);
        }
        
        return result;
    }
    
    /**
     * Generate public commitments for the polynomial
     */
    generateCommitments() {
        return this.coefficients.map(coeff => gPowP(coeff));
    }
    
    /**
     * Get the secret (constant term)
     */
    getSecret() {
        return this.coefficients[0];
    }
    
    /**
     * Get the degree of the polynomial
     */
    getDegree() {
        return this.coefficients.length - 1;
    }
    
    toJSON() {
        return {
            coefficients: this.coefficients.map(c => c.toJSON())
        };
    }
    
    static fromJSON(json) {
        return new ElectionPolynomial(json.coefficients);
    }
    
    toString() {
        return `ElectionPolynomial(degree=${this.getDegree()})`;
    }
}

/**
 * Coefficient for polynomial sharing
 */
class Coefficient {
    constructor(owner, coefficient, commitment) {
        this.owner = owner;
        this.coefficient = coefficient instanceof ElementModQ ? coefficient : new ElementModQ(coefficient);
        this.commitment = commitment instanceof ElementModP ? commitment : new ElementModP(commitment);
    }
    
    toJSON() {
        return {
            owner: this.owner,
            coefficient: this.coefficient.toJSON(),
            commitment: this.commitment.toJSON()
        };
    }
    
    static fromJSON(json) {
        return new Coefficient(json.owner, json.coefficient, json.commitment);
    }
}

/**
 * Secret Coefficient (encrypted for specific guardian)
 */
class SecretCoefficient extends Coefficient {
    constructor(owner, coefficient, commitment, encryptedCoefficient = null) {
        super(owner, coefficient, commitment);
        this.encryptedCoefficient = encryptedCoefficient;
    }
    
    toJSON() {
        const json = super.toJSON();
        json.encrypted_coefficient = this.encryptedCoefficient;
        return json;
    }
    
    static fromJSON(json) {
        return new SecretCoefficient(
            json.owner,
            json.coefficient,
            json.commitment,
            json.encrypted_coefficient || json.encryptedCoefficient
        );
    }
}

/**
 * Public Commitment
 */
class PublicCommitment {
    constructor(owner, commitment) {
        this.owner = owner;
        this.commitment = commitment instanceof ElementModP ? commitment : new ElementModP(commitment);
    }
    
    toJSON() {
        return {
            owner: this.owner,
            commitment: this.commitment.toJSON()
        };
    }
    
    static fromJSON(json) {
        return new PublicCommitment(json.owner, json.commitment);
    }
}

/**
 * Election Key Pair
 */
class ElectionKeyPair {
    constructor(secretKey, publicKey) {
        this.secretKey = secretKey instanceof ElementModQ ? secretKey : new ElementModQ(secretKey);
        this.publicKey = publicKey instanceof ElementModP ? publicKey : new ElementModP(publicKey);
    }
    
    static generate() {
        const secret = randomQ();
        const publicKey = gPowP(secret);
        return new ElectionKeyPair(secret, publicKey);
    }
    
    toJSON() {
        return {
            secret_key: this.secretKey.toJSON(),
            public_key: this.publicKey.toJSON()
        };
    }
    
    static fromJSON(json) {
        return new ElectionKeyPair(
            json.secret_key || json.secretKey,
            json.public_key || json.publicKey
        );
    }
    
    toString() {
        return `ElectionKeyPair(publicKey=${this.publicKey.toString()})`;
    }
}

/**
 * Election Public Key
 */
class ElectionPublicKey {
    constructor(publicKey) {
        this.publicKey = publicKey instanceof ElementModP ? publicKey : new ElementModP(publicKey);
    }
    
    toJSON() {
        return {
            public_key: this.publicKey.toJSON()
        };
    }
    
    static fromJSON(json) {
        return new ElectionPublicKey(json.public_key || json.publicKey);
    }
    
    toString() {
        return `ElectionPublicKey(${this.publicKey.toString()})`;
    }
}

/**
 * Guardian
 */
class Guardian {
    constructor(guardianId, sequence, numberOfGuardians, quorum) {
        this.guardianId = guardianId;
        this.sequence = sequence;
        this.numberOfGuardians = numberOfGuardians;
        this.quorum = quorum;
        this.electionKeyPair = null;
        this.polynomial = null;
        this.commitments = [];
        this.backupKeys = new Map(); // guardianId -> backup key
        this.publicKeys = new Map(); // guardianId -> public key
        this.proofs = new Map(); // guardianId -> proof
    }
    
    /**
     * Generate election key pair and polynomial for secret sharing
     */
    generateKeys() {
        // Generate election key pair
        this.electionKeyPair = ElectionKeyPair.generate();
        
        // Generate polynomial for secret sharing (degree = quorum - 1)
        this.polynomial = ElectionPolynomial.generate(
            this.quorum - 1,
            this.electionKeyPair.secretKey
        );
        
        // Generate public commitments
        this.commitments = this.polynomial.generateCommitments();
        
        return {
            publicKey: this.electionKeyPair.publicKey,
            commitments: this.commitments
        };
    }
    
    /**
     * Generate backup for another guardian
     */
    generateBackup(otherGuardianId, otherSequence) {
        if (!this.polynomial) {
            throw new Error('Must generate keys first');
        }
        
        // Evaluate polynomial at the other guardian's sequence
        const backupValue = this.polynomial.evaluate(otherSequence);
        
        // Store backup
        this.backupKeys.set(otherGuardianId, backupValue);
        
        return backupValue;
    }
    
    /**
     * Receive backup from another guardian
     */
    receiveBackup(fromGuardianId, backupValue) {
        if (backupValue instanceof ElementModQ) {
            this.backupKeys.set(fromGuardianId, backupValue);
        } else {
            this.backupKeys.set(fromGuardianId, new ElementModQ(backupValue));
        }
    }
    
    /**
     * Verify backup using public commitments
     */
    verifyBackup(fromGuardianId, backupValue, commitments) {
        if (!backupValue || !commitments || commitments.length === 0) {
            return false;
        }
        
        try {
            const backup = backupValue instanceof ElementModQ ? backupValue : new ElementModQ(backupValue);
            
            // Compute expected commitment
            let expectedCommitment = commitments[0]; // C_0
            let sequencePower = new ElementModQ(1);
            
            for (let i = 1; i < commitments.length; i++) {
                sequencePower = sequencePower.multiply(new ElementModQ(this.sequence));
                const commitment = commitments[i] instanceof ElementModP ? commitments[i] : new ElementModP(commitments[i]);
                expectedCommitment = expectedCommitment.multiply(commitment.pow(sequencePower));
            }
            
            // Verify: g^backup_value = expected_commitment
            const computedCommitment = gPowP(backup);
            return computedCommitment.equals(expectedCommitment);
        } catch (error) {
            console.error('Backup verification error:', error);
            return false;
        }
    }
    
    /**
     * Generate Schnorr proof for public key
     */
    generateProof() {
        if (!this.electionKeyPair) {
            throw new Error('Must generate keys first');
        }
        
        const u = randomQ();
        const commitment = gPowP(u);
        
        const challenge = hashElems(
            this.guardianId,
            this.electionKeyPair.publicKey.toHex(),
            commitment.toHex()
        );
        
        const response = u.add(challenge.multiply(this.electionKeyPair.secretKey));
        
        const proof = {
            commitment: commitment,
            challenge: challenge,
            response: response
        };
        
        this.proofs.set(this.guardianId, proof);
        return proof;
    }
    
    /**
     * Verify Schnorr proof
     */
    verifyProof(guardianId, publicKey, proof) {
        try {
            const { commitment, challenge, response } = proof;
            
            // Recompute challenge
            const expectedChallenge = hashElems(
                guardianId,
                publicKey.toHex(),
                commitment.toHex()
            );
            
            if (!challenge.equals(expectedChallenge)) {
                return false;
            }
            
            // Verify: g^response = commitment * publicKey^challenge
            const leftSide = gPowP(response);
            const rightSide = commitment.multiply(publicKey.pow(challenge));
            
            return leftSide.equals(rightSide);
        } catch (error) {
            console.error('Proof verification error:', error);
            return false;
        }
    }
    
    /**
     * Complete key ceremony by storing other guardians' public keys
     */
    completeKeyCeremony(guardianPublicKeys) {
        for (const [guardianId, publicKey] of Object.entries(guardianPublicKeys)) {
            if (guardianId !== this.guardianId) {
                this.publicKeys.set(guardianId, publicKey instanceof ElementModP ? publicKey : new ElementModP(publicKey));
            }
        }
    }
    
    toJSON() {
        return {
            guardian_id: this.guardianId,
            sequence: this.sequence,
            number_of_guardians: this.numberOfGuardians,
            quorum: this.quorum,
            election_key_pair: this.electionKeyPair ? this.electionKeyPair.toJSON() : null,
            polynomial: this.polynomial ? this.polynomial.toJSON() : null,
            commitments: this.commitments.map(c => c.toJSON()),
            backup_keys: Object.fromEntries(
                Array.from(this.backupKeys.entries()).map(([k, v]) => [k, v.toJSON()])
            ),
            public_keys: Object.fromEntries(
                Array.from(this.publicKeys.entries()).map(([k, v]) => [k, v.toJSON()])
            ),
            proofs: Object.fromEntries(
                Array.from(this.proofs.entries()).map(([k, v]) => [k, {
                    commitment: v.commitment.toJSON(),
                    challenge: v.challenge.toJSON(),
                    response: v.response.toJSON()
                }])
            )
        };
    }
    
    static fromJSON(json) {
        const guardian = new Guardian(
            json.guardian_id || json.guardianId,
            json.sequence,
            json.number_of_guardians || json.numberOfGuardians,
            json.quorum
        );
        
        if (json.election_key_pair || json.electionKeyPair) {
            guardian.electionKeyPair = ElectionKeyPair.fromJSON(json.election_key_pair || json.electionKeyPair);
        }
        
        if (json.polynomial) {
            guardian.polynomial = ElectionPolynomial.fromJSON(json.polynomial);
        }
        
        guardian.commitments = (json.commitments || []).map(c => new ElementModP(c));
        
        // Restore backup keys
        if (json.backup_keys || json.backupKeys) {
            const backupKeys = json.backup_keys || json.backupKeys;
            for (const [guardianId, key] of Object.entries(backupKeys)) {
                guardian.backupKeys.set(guardianId, new ElementModQ(key));
            }
        }
        
        // Restore public keys
        if (json.public_keys || json.publicKeys) {
            const publicKeys = json.public_keys || json.publicKeys;
            for (const [guardianId, key] of Object.entries(publicKeys)) {
                guardian.publicKeys.set(guardianId, new ElementModP(key));
            }
        }
        
        // Restore proofs
        if (json.proofs) {
            for (const [guardianId, proof] of Object.entries(json.proofs)) {
                guardian.proofs.set(guardianId, {
                    commitment: new ElementModP(proof.commitment),
                    challenge: new ElementModQ(proof.challenge),
                    response: new ElementModQ(proof.response)
                });
            }
        }
        
        return guardian;
    }
    
    toString() {
        return `Guardian(${this.guardianId}, sequence=${this.sequence}, quorum=${this.quorum}/${this.numberOfGuardians})`;
    }
}

/**
 * Key Ceremony Mediator
 */
class KeyCeremonyMediator {
    constructor(numberOfGuardians, quorum) {
        this.numberOfGuardians = numberOfGuardians;
        this.quorum = quorum;
        this.guardians = new Map();
        this.publicKeys = new Map();
        this.commitments = new Map();
        this.backups = new Map();
        this.jointPublicKey = null;
        this.commitmentHash = null;
        this.isComplete = false;
    }
    
    /**
     * Add guardian to ceremony
     */
    addGuardian(guardian) {
        if (!(guardian instanceof Guardian)) {
            throw new Error('Must provide Guardian instance');
        }
        
        this.guardians.set(guardian.guardianId, guardian);
        
        if (guardian.electionKeyPair) {
            this.publicKeys.set(guardian.guardianId, guardian.electionKeyPair.publicKey);
        }
        
        if (guardian.commitments.length > 0) {
            this.commitments.set(guardian.guardianId, guardian.commitments);
        }
    }
    
    /**
     * Exchange public keys between guardians
     */
    exchangePublicKeys() {
        for (const [guardianId, guardian] of this.guardians) {
            const otherPublicKeys = {};
            for (const [otherId, otherGuardian] of this.guardians) {
                if (otherId !== guardianId && otherGuardian.electionKeyPair) {
                    otherPublicKeys[otherId] = otherGuardian.electionKeyPair.publicKey;
                }
            }
            guardian.completeKeyCeremony(otherPublicKeys);
        }
    }
    
    /**
     * Exchange backup values between guardians
     */
    exchangeBackups() {
        // Generate backups
        for (const [guardianId, guardian] of this.guardians) {
            for (const [otherId, otherGuardian] of this.guardians) {
                if (guardianId !== otherId) {
                    const backup = guardian.generateBackup(otherId, otherGuardian.sequence);
                    
                    // Store backup for exchange
                    if (!this.backups.has(otherId)) {
                        this.backups.set(otherId, new Map());
                    }
                    this.backups.get(otherId).set(guardianId, backup);
                }
            }
        }
        
        // Distribute backups
        for (const [guardianId, guardian] of this.guardians) {
            if (this.backups.has(guardianId)) {
                for (const [fromId, backup] of this.backups.get(guardianId)) {
                    guardian.receiveBackup(fromId, backup);
                }
            }
        }
    }
    
    /**
     * Verify all backups
     */
    verifyBackups() {
        for (const [guardianId, guardian] of this.guardians) {
            for (const [fromId, backup] of guardian.backupKeys) {
                const fromCommitments = this.commitments.get(fromId);
                if (!guardian.verifyBackup(fromId, backup, fromCommitments)) {
                    throw new Error(`Backup verification failed: ${fromId} -> ${guardianId}`);
                }
            }
        }
        return true;
    }
    
    /**
     * Compute joint public key
     */
    computeJointPublicKey() {
        if (this.publicKeys.size < this.numberOfGuardians) {
            throw new Error('Not all guardians have submitted public keys');
        }
        
        // Joint public key is the product of all guardian public keys
        const publicKeyValues = Array.from(this.publicKeys.values());
        let joint = publicKeyValues[0];
        
        for (let i = 1; i < publicKeyValues.length; i++) {
            joint = joint.multiply(publicKeyValues[i]);
        }
        
        this.jointPublicKey = joint;
        return joint;
    }
    
    /**
     * Compute commitment hash
     */
    computeCommitmentHash() {
        if (this.commitments.size < this.numberOfGuardians) {
            throw new Error('Not all guardians have submitted commitments');
        }
        
        const elements = [];
        
        // Sort guardians by ID for deterministic hash
        const sortedGuardianIds = Array.from(this.commitments.keys()).sort();
        
        for (const guardianId of sortedGuardianIds) {
            elements.push(guardianId);
            const commitments = this.commitments.get(guardianId);
            for (const commitment of commitments) {
                elements.push(commitment.toHex());
            }
        }
        
        this.commitmentHash = hashElems(...elements);
        return this.commitmentHash;
    }
    
    /**
     * Complete key ceremony
     */
    complete() {
        this.exchangePublicKeys();
        this.exchangeBackups();
        this.verifyBackups();
        this.computeJointPublicKey();
        this.computeCommitmentHash();
        this.isComplete = true;
        
        return {
            jointPublicKey: this.jointPublicKey,
            commitmentHash: this.commitmentHash,
            guardians: Array.from(this.guardians.values())
        };
    }
    
    toJSON() {
        return {
            number_of_guardians: this.numberOfGuardians,
            quorum: this.quorum,
            guardians: Array.from(this.guardians.values()).map(g => g.toJSON()),
            joint_public_key: this.jointPublicKey ? this.jointPublicKey.toJSON() : null,
            commitment_hash: this.commitmentHash ? this.commitmentHash.toJSON() : null,
            is_complete: this.isComplete
        };
    }
    
    static fromJSON(json) {
        const mediator = new KeyCeremonyMediator(
            json.number_of_guardians || json.numberOfGuardians,
            json.quorum
        );
        
        if (json.guardians) {
            json.guardians.forEach(guardianData => {
                const guardian = Guardian.fromJSON(guardianData);
                mediator.addGuardian(guardian);
            });
        }
        
        if (json.joint_public_key || json.jointPublicKey) {
            mediator.jointPublicKey = new ElementModP(json.joint_public_key || json.jointPublicKey);
        }
        
        if (json.commitment_hash || json.commitmentHash) {
            mediator.commitmentHash = new ElementModQ(json.commitment_hash || json.commitmentHash);
        }
        
        mediator.isComplete = json.is_complete || json.isComplete || false;
        
        return mediator;
    }
    
    toString() {
        return `KeyCeremonyMediator(${this.numberOfGuardians} guardians, quorum=${this.quorum}, complete=${this.isComplete})`;
    }
}

module.exports = {
    ElectionPolynomial,
    Coefficient,
    SecretCoefficient,
    PublicCommitment,
    ElectionKeyPair,
    ElectionPublicKey,
    Guardian,
    KeyCeremonyMediator
};
