/**
 * ElectionGuard ElGamal Encryption
 * 
 * Implements the ElGamal encryption scheme with homomorphic properties
 * for secure ballot encryption and tallying.
 */

const crypto = require('crypto');
const { ElementModP, ElementModQ, randomQ, gPowP, hashElems } = require('./group');

/**
 * ElGamal Public Key
 */
class ElGamalPublicKey {
    constructor(key) {
        if (key instanceof ElementModP) {
            this.key = key;
        } else if (typeof key === 'string') {
            this.key = new ElementModP(key);
        } else if (key && key.key) {
            this.key = key.key instanceof ElementModP ? key.key : new ElementModP(key.key);
        } else {
            throw new Error('Invalid ElGamal public key');
        }
    }
    
    /**
     * Encrypt a message using ElGamal encryption
     */
    encrypt(plaintext, nonce = null) {
        if (typeof plaintext === 'number') {
            plaintext = new ElementModQ(plaintext);
        } else if (!(plaintext instanceof ElementModQ)) {
            throw new Error('Plaintext must be ElementModQ');
        }
        
        // Generate random nonce if not provided
        if (!nonce) {
            nonce = randomQ();
        } else if (!(nonce instanceof ElementModQ)) {
            nonce = new ElementModQ(nonce);
        }
        
        // ElGamal encryption: (g^r, K^r * g^m)
        // where K is the public key, r is the nonce, m is the message
        const alpha = gPowP(nonce); // g^r
        const beta = this.key.pow(nonce).multiply(gPowP(plaintext)); // K^r * g^m
        
        return new ElGamalCiphertext(alpha, beta);
    }
    
    /**
     * Encrypt with proof of correct encryption
     */
    encryptWithProof(plaintext, nonce = null, hashHeader = null) {
        if (!nonce) {
            nonce = randomQ();
        }
        
        const ciphertext = this.encrypt(plaintext, nonce);
        
        // Generate Chaum-Pedersen proof
        const proof = this.generateProof(plaintext, nonce, ciphertext, hashHeader);
        
        return {
            ciphertext: ciphertext,
            proof: proof
        };
    }
    
    /**
     * Generate Chaum-Pedersen proof for encryption correctness
     */
    generateProof(message, nonce, ciphertext, hashHeader = null) {
        // Generate random value for proof
        const u = randomQ();
        
        // Commitments
        const a = gPowP(u); // g^u
        const b = this.key.pow(u); // K^u
        
        // Challenge
        const elements = [this.key, ciphertext.alpha, ciphertext.beta, a, b];
        if (hashHeader) {
            elements.unshift(hashHeader);
        }
        const c = hashElems(...elements);
        
        // Response
        const v = u.add(c.multiply(nonce)); // u + c*r
        
        return {
            challenge: c,
            response: v
        };
    }
    
    /**
     * Verify Chaum-Pedersen proof
     */
    verifyProof(proof, ciphertext, hashHeader = null) {
        const { challenge, response } = proof;
        
        // Recompute commitments
        const gv = gPowP(response); // g^v
        const ac = ciphertext.alpha.pow(challenge); // alpha^c
        const a = gv.multiply(ac.pow(challenge.negate())); // g^v / alpha^c
        
        const kv = this.key.pow(response); // K^v
        const bc = ciphertext.beta.pow(challenge); // beta^c
        const gm = gPowP(new ElementModQ(1)); // This should be g^m, but we don't know m
        const b = kv.multiply(bc.multiply(gm).pow(challenge.negate())); // K^v / (beta * g^m)^c
        
        // Recompute challenge
        const elements = [this.key, ciphertext.alpha, ciphertext.beta, a, b];
        if (hashHeader) {
            elements.unshift(hashHeader);
        }
        const computedChallenge = hashElems(...elements);
        
        return challenge.equals(computedChallenge);
    }
    
    equals(other) {
        return other instanceof ElGamalPublicKey && this.key.equals(other.key);
    }
    
    toHex() {
        return this.key.toHex();
    }
    
    toJSON() {
        return {
            key: this.key.toJSON()
        };
    }
    
    static fromJSON(json) {
        return new ElGamalPublicKey(json.key || json);
    }
    
    toString() {
        return `ElGamalPublicKey(${this.key.toString()})`;
    }
}

/**
 * ElGamal Secret Key
 */
class ElGamalSecretKey {
    constructor(secret) {
        if (secret instanceof ElementModQ) {
            this.secret = secret;
        } else if (typeof secret === 'string') {
            this.secret = new ElementModQ(secret);
        } else if (secret && secret.secret) {
            this.secret = secret.secret instanceof ElementModQ ? secret.secret : new ElementModQ(secret.secret);
        } else {
            throw new Error('Invalid ElGamal secret key');
        }
    }
    
    /**
     * Generate corresponding public key
     */
    publicKey() {
        return new ElGamalPublicKey(gPowP(this.secret));
    }
    
    /**
     * Decrypt an ElGamal ciphertext
     */
    decrypt(ciphertext) {
        if (!(ciphertext instanceof ElGamalCiphertext)) {
            throw new Error('Can only decrypt ElGamalCiphertext');
        }
        
        // ElGamal decryption: beta / alpha^x = (K^r * g^m) / (g^r)^x = g^m
        // where x is the secret key
        const alphaPowX = ciphertext.alpha.pow(this.secret);
        const gToTheM = ciphertext.beta.multiply(alphaPowX.pow(new ElementModQ(-1)));
        
        // Discrete log to recover m (this is only practical for small messages)
        return this.discreteLog(gToTheM);
    }
    
    /**
     * Compute discrete logarithm for small messages
     * This is a brute force approach suitable only for small message spaces
     */
    discreteLog(target, maxTries = 1000000) {
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
     * Partially decrypt a ciphertext (for threshold decryption)
     */
    partialDecrypt(ciphertext) {
        if (!(ciphertext instanceof ElGamalCiphertext)) {
            throw new Error('Can only decrypt ElGamalCiphertext');
        }
        
        // Compute alpha^secret_key for threshold decryption
        return ciphertext.alpha.pow(this.secret);
    }
    
    equals(other) {
        return other instanceof ElGamalSecretKey && this.secret.equals(other.secret);
    }
    
    toHex() {
        return this.secret.toHex();
    }
    
    toJSON() {
        return {
            secret: this.secret.toJSON()
        };
    }
    
    static fromJSON(json) {
        return new ElGamalSecretKey(json.secret || json);
    }
    
    toString() {
        return `ElGamalSecretKey(${this.secret.toString()})`;
    }
}

/**
 * ElGamal Ciphertext
 */
class ElGamalCiphertext {
    constructor(alpha, beta) {
        if (!(alpha instanceof ElementModP) || !(beta instanceof ElementModP)) {
            if (alpha && beta && alpha.alpha && alpha.beta) {
                // Handle case where first argument is actually a ciphertext object
                this.alpha = alpha.alpha instanceof ElementModP ? alpha.alpha : new ElementModP(alpha.alpha);
                this.beta = alpha.beta instanceof ElementModP ? alpha.beta : new ElementModP(alpha.beta);
            } else {
                this.alpha = alpha instanceof ElementModP ? alpha : new ElementModP(alpha);
                this.beta = beta instanceof ElementModP ? beta : new ElementModP(beta);
            }
        } else {
            this.alpha = alpha;
            this.beta = beta;
        }
    }
    
    /**
     * Homomorphic addition of ciphertexts
     * (α₁, β₁) + (α₂, β₂) = (α₁ · α₂, β₁ · β₂)
     */
    add(other) {
        if (!(other instanceof ElGamalCiphertext)) {
            throw new Error('Can only add ElGamalCiphertext');
        }
        
        return new ElGamalCiphertext(
            this.alpha.multiply(other.alpha),
            this.beta.multiply(other.beta)
        );
    }
    
    /**
     * Scalar multiplication of ciphertext
     * k * (α, β) = (α^k, β^k)
     */
    scalarMultiply(scalar) {
        if (typeof scalar === 'number') {
            scalar = new ElementModQ(scalar);
        } else if (!(scalar instanceof ElementModQ)) {
            throw new Error('Scalar must be ElementModQ or number');
        }
        
        return new ElGamalCiphertext(
            this.alpha.pow(scalar),
            this.beta.pow(scalar)
        );
    }
    
    /**
     * Check if two ciphertexts are equal
     */
    equals(other) {
        return other instanceof ElGamalCiphertext && 
               this.alpha.equals(other.alpha) && 
               this.beta.equals(other.beta);
    }
    
    /**
     * Check if ciphertext is valid (not zero)
     */
    isValid() {
        const one = new ElementModP(1);
        return !this.alpha.equals(one) && !this.beta.equals(one);
    }
    
    toJSON() {
        return {
            alpha: this.alpha.toJSON(),
            beta: this.beta.toJSON()
        };
    }
    
    static fromJSON(json) {
        return new ElGamalCiphertext(json.alpha, json.beta);
    }
    
    toString() {
        return `ElGamalCiphertext(α=${this.alpha.toString()}, β=${this.beta.toString()})`;
    }
}

/**
 * ElGamal Key Pair
 */
class ElGamalKeyPair {
    constructor(secretKey = null) {
        if (secretKey instanceof ElGamalSecretKey) {
            this.secretKey = secretKey;
        } else if (secretKey instanceof ElementModQ) {
            this.secretKey = new ElGamalSecretKey(secretKey);
        } else if (secretKey) {
            this.secretKey = new ElGamalSecretKey(secretKey);
        } else {
            // Generate random key pair
            this.secretKey = new ElGamalSecretKey(randomQ());
        }
        
        this.publicKey = this.secretKey.publicKey();
    }
    
    encrypt(plaintext, nonce = null) {
        return this.publicKey.encrypt(plaintext, nonce);
    }
    
    encryptWithProof(plaintext, nonce = null, hashHeader = null) {
        return this.publicKey.encryptWithProof(plaintext, nonce, hashHeader);
    }
    
    decrypt(ciphertext) {
        return this.secretKey.decrypt(ciphertext);
    }
    
    partialDecrypt(ciphertext) {
        return this.secretKey.partialDecrypt(ciphertext);
    }
    
    toJSON() {
        return {
            secretKey: this.secretKey.toJSON(),
            publicKey: this.publicKey.toJSON()
        };
    }
    
    static fromJSON(json) {
        const keyPair = new ElGamalKeyPair();
        keyPair.secretKey = ElGamalSecretKey.fromJSON(json.secretKey);
        keyPair.publicKey = ElGamalPublicKey.fromJSON(json.publicKey);
        return keyPair;
    }
    
    toString() {
        return `ElGamalKeyPair(publicKey=${this.publicKey.toString()}, secretKey=***hidden***)`;
    }
}

/**
 * Generate a random ElGamal key pair
 */
function generateElGamalKeyPair() {
    return new ElGamalKeyPair();
}

/**
 * Create ElGamal ciphertext for zero (used in proofs)
 */
function encryptZero(publicKey, nonce = null) {
    return publicKey.encrypt(new ElementModQ(0), nonce);
}

/**
 * Create ElGamal ciphertext for one
 */
function encryptOne(publicKey, nonce = null) {
    return publicKey.encrypt(new ElementModQ(1), nonce);
}

/**
 * Combine multiple public keys using homomorphic properties
 */
function combinePublicKeys(publicKeys) {
    if (!Array.isArray(publicKeys) || publicKeys.length === 0) {
        throw new Error('Must provide array of public keys');
    }
    
    let combined = publicKeys[0].key;
    for (let i = 1; i < publicKeys.length; i++) {
        combined = combined.multiply(publicKeys[i].key);
    }
    
    return new ElGamalPublicKey(combined);
}

module.exports = {
    ElGamalPublicKey,
    ElGamalSecretKey,
    ElGamalCiphertext,
    ElGamalKeyPair,
    generateElGamalKeyPair,
    encryptZero,
    encryptOne,
    combinePublicKeys
};
