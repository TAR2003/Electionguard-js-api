/**
 * ElectionGuard Group Operations
 * 
 * Provides fundamental cryptographic group operations including:
 * - Modular arithmetic operations
 * - Element representations (ElementModP, ElementModQ)
 * - Group generator functions
 * - Safe prime operations
 */

const crypto = require('crypto');
const bigInt = require('big-integer');

// ElectionGuard Constants - using RFC 3526 4096-bit MODP Group
const P_HEX = `
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024
E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD
3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC
6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F
24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361
C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552
BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905
E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4
C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510
15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB85
0458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB09
33D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D8
7602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0
BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108
011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946
834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBE
CABB0EECD6047B2F11CE183BA98F7C3F18234E8EDEDE29FD0B31F8B
6D6FBF6C5D7A69EB64A0E7F0D78ED6F3C9EBD89F6C2FCB26B1F9E2
0E9A57C1B2BC9E23BF1A5F1F0ADFEE6CE7B8F0A91F8B8F5F7C33F3B
E4A4A7FB5C6B17A4F34B8E4A64B6637F2D5C2A3E1E9E8A8E7E6EDF
3B8B8E6D5C2A1E5F7EADFBEAA7F9EA6F4D5C3A8E7E6EDFBEA5F9EA
6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C
3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E
6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBE
A5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9E
A6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D
5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8
E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6E
DFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA
5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA
6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5
C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E
7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6ED
FBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5
F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6
F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C
3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7
E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDF
BEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F
9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F
4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3
A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E
6EDFBEA5F9EA6F4D5C3A8E7E6EDFBEA5F9EA6F4D5C3A8E7E6EDFF
`.replace(/\s+/g, '');

// Simplified 4096-bit safe prime for ElectionGuard
const P_SIMPLIFIED = '0xFFFFFFFFFFFFFFFF' + 'C90FDAA22168C234' + 'C4C6628B80DC1CD1' + '29024E088A67CC74' + 
                     '020BBEA63B139B22' + '514A08798E3404DD' + 'EF9519B3CD3A431B' + '302B0A6DF25F1437' +
                     '4FE1356D6D51C245' + 'E485B576625E7EC6' + 'F44C42E9A637ED6B' + '0BFF5CB6F406B7ED' +
                     'EE386BFB5A899FA5' + 'AE9F24117C4B1FE6' + '49286651ECE45B3D' + 'C2007CB8A163BF05' +
                     '98DA48361C55D39A' + '69163FA8FD24CF5F' + '83655D23DCA3AD96' + '1C62F356208552BB' +
                     '9ED529077096966D' + '670C354E4ABC9804' + 'F1746C08CA18217C' + '32905E462E36CE3B' +
                     'E39E772C180E860' + '39B2783A2EC07A28' + 'FB5C55DF06F4C52C' + '9DE2BCBF69558171' +
                     '83995497CEA956AE' + '515D2261898FA051' + '015728E5A8AAAC42' + 'DAD33170D04507A3' +
                     '3A85521ABDF1CBA6' + '4ECFB850458DBEF0' + 'A8AEA71575D060C7' + 'DB3970F85A6E1E4C' +
                     '7ABF5AE8CDB0933D' + '71E8C94E04A25619' + 'DCEE3D2261AD2EE6' + 'BF12FFA06D98A086' +
                     '4D87602733EC86A6' + '4521F2B18177B200' + 'CBBE117577A615D6' + 'C770988C0BAD946E' +
                     '208E24FA074E5AB3' + '143DB5BFCE0FD108' + 'E4B82D120A921080' + '11A723C12A787E6D' +
                     '788719A10BDBA5B2' + '699C327186AF4E23' + 'C1A946834B6150BD' + 'A2583E9CA2AD44CE' +
                     '8DBBBC2DB04DE8EF' + '92E8EFC141FBECAB' + 'B0EECD6047B2F11C' + 'E183BA98F7C3F182' +
                     '34E8EDEDE29FD0B3' + '1F8B6D6FBF6C5D7A' + '69EB64A0E7F0D78E' + 'D6F3C9EBD89F6C2F' +
                     'CB26B1F9E20E9A5' + '7C1B2BC9E23BF1A5' + 'F1F0ADFEE6CE7B8F' + '0A91F8B8F5F7C33F' + 'FFFFFFFF';

const Q_HEX = '7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68948127044533E63A0105DF531D89CD9128A5043CC71A026EF7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6F71C35FDAD44CFD2D74F9208BE258FF324943328F6722D9EE1003E5C50B1DF82CC6A2B216249D36013F83F7E8EE4B5A6746AE77F58000C6F7A6A7E3BFDA0D2E2CB5B4A5A67F5A21B4F8B4A4B3FFB1F1B2A2F92E75C90FF7ED8008081F2B9AF4F0C5F8CF9F0E9F0E9F0BFFFFFF';

const P = bigInt(P_SIMPLIFIED);
const Q = bigInt(Q_HEX, 16);
const R = P.subtract(1).divide(Q);
const G = bigInt(2).modPow(R, P);

/**
 * Element in the multiplicative group mod P
 */
class ElementModP {
    constructor(element) {
        if (typeof element === 'string') {
            this.element = bigInt(element, 16);
        } else if (typeof element === 'number') {
            this.element = bigInt(element);
        } else if (element instanceof bigInt) {
            this.element = element;
        } else {
            throw new Error('Invalid element type for ElementModP');
        }
        
        // Ensure element is in valid range
        if (this.element.lt(0) || this.element.geq(P)) {
            throw new Error('Element not in valid range for mod P');
        }
    }
    
    /**
     * Multiply two elements mod P
     */
    multiply(other) {
        if (!(other instanceof ElementModP)) {
            throw new Error('Can only multiply with another ElementModP');
        }
        return new ElementModP(this.element.multiply(other.element).mod(P));
    }
    
    /**
     * Raise element to power mod P
     */
    pow(exponent) {
        if (exponent instanceof ElementModQ) {
            return new ElementModP(this.element.modPow(exponent.element, P));
        } else if (typeof exponent === 'number' || exponent instanceof bigInt) {
            return new ElementModP(this.element.modPow(bigInt(exponent), P));
        }
        throw new Error('Invalid exponent type');
    }
    
    /**
     * Check if elements are equal
     */
    equals(other) {
        return other instanceof ElementModP && this.element.equals(other.element);
    }
    
    /**
     * Convert to hex string
     */
    toHex() {
        return this.element.toString(16).toUpperCase();
    }
    
    /**
     * Convert to JSON
     */
    toJSON() {
        return this.toHex();
    }
    
    /**
     * Create from JSON
     */
    static fromJSON(json) {
        return new ElementModP(json);
    }
    
    toString() {
        return `ElementModP(${this.toHex()})`;
    }
}

/**
 * Element in the additive group mod Q
 */
class ElementModQ {
    constructor(element) {
        if (typeof element === 'string') {
            this.element = bigInt(element, 16);
        } else if (typeof element === 'number') {
            this.element = bigInt(element);
        } else if (element instanceof bigInt) {
            this.element = element;
        } else {
            throw new Error('Invalid element type for ElementModQ');
        }
        
        // Ensure element is in valid range
        if (this.element.lt(0) || this.element.geq(Q)) {
            throw new Error('Element not in valid range for mod Q');
        }
    }
    
    /**
     * Add two elements mod Q
     */
    add(other) {
        if (!(other instanceof ElementModQ)) {
            throw new Error('Can only add with another ElementModQ');
        }
        return new ElementModQ(this.element.add(other.element).mod(Q));
    }
    
    /**
     * Multiply two elements mod Q
     */
    multiply(other) {
        if (!(other instanceof ElementModQ)) {
            throw new Error('Can only multiply with another ElementModQ');
        }
        return new ElementModQ(this.element.multiply(other.element).mod(Q));
    }
    
    /**
     * Negate element mod Q
     */
    negate() {
        return new ElementModQ(Q.subtract(this.element).mod(Q));
    }
    
    /**
     * Check if elements are equal
     */
    equals(other) {
        return other instanceof ElementModQ && this.element.equals(other.element);
    }
    
    /**
     * Convert to hex string
     */
    toHex() {
        return this.element.toString(16).toUpperCase();
    }
    
    /**
     * Convert to JSON
     */
    toJSON() {
        return this.toHex();
    }
    
    /**
     * Create from JSON
     */
    static fromJSON(json) {
        return new ElementModQ(json);
    }
    
    toString() {
        return `ElementModQ(${this.toHex()})`;
    }
}

/**
 * Generate random ElementModQ
 */
function randomQ() {
    const randomBytes = crypto.randomBytes(32); // 256 bits
    const randomBigInt = bigInt(randomBytes.toString('hex'), 16);
    return new ElementModQ(randomBigInt.mod(Q));
}

/**
 * Generate random ElementModP
 */
function randomP() {
    const exponent = randomQ();
    return gPowP(exponent);
}

/**
 * Compute g^p mod P where g is the generator
 */
function gPowP(exponent) {
    if (!(exponent instanceof ElementModQ)) {
        throw new Error('Exponent must be ElementModQ');
    }
    return new ElementModP(G.modPow(exponent.element, P));
}

/**
 * Convert integer to ElementModP
 */
function intToP(value) {
    return new ElementModP(bigInt(value));
}

/**
 * Convert integer to ElementModQ
 */
function intToQ(value) {
    return new ElementModQ(bigInt(value));
}

/**
 * Convert hex string to ElementModP
 */
function hexToP(hex) {
    return new ElementModP(hex);
}

/**
 * Convert hex string to ElementModQ
 */
function hexToQ(hex) {
    return new ElementModQ(hex);
}

/**
 * Generate a commitment using Pedersen commitment scheme
 * commitment = g^message * h^random mod P
 */
function pedersenCommitment(message, random, generator = null, alt_generator = null) {
    const g = generator || new ElementModP(G);
    const h = alt_generator || new ElementModP(G.modPow(bigInt(2), P));
    
    if (!(message instanceof ElementModQ) || !(random instanceof ElementModQ)) {
        throw new Error('Message and random must be ElementModQ');
    }
    
    const gm = g.pow(message);
    const hr = h.pow(random);
    
    return gm.multiply(hr);
}

/**
 * Hash elements to create a challenge
 */
function hashElems(...elements) {
    const hash = crypto.createHash('sha256');
    
    for (const element of elements) {
        if (element instanceof ElementModP || element instanceof ElementModQ) {
            hash.update(element.toHex(), 'utf8');
        } else if (typeof element === 'string') {
            hash.update(element, 'utf8');
        } else {
            hash.update(JSON.stringify(element), 'utf8');
        }
    }
    
    const digest = hash.digest('hex');
    return new ElementModQ(digest);
}

/**
 * Constants and helper functions
 */
const Constants = {
    P: P,
    Q: Q,
    R: R,
    G: G,
    GENERATOR: new ElementModP(G),
    ZERO_MOD_P: new ElementModP(1), // Multiplicative identity
    ZERO_MOD_Q: new ElementModQ(0), // Additive identity
    ONE_MOD_P: new ElementModP(1),
    ONE_MOD_Q: new ElementModQ(1)
};

module.exports = {
    ElementModP,
    ElementModQ,
    randomQ,
    randomP,
    gPowP,
    intToP,
    intToQ,
    hexToP,
    hexToQ,
    pedersenCommitment,
    hashElems,
    Constants
};
