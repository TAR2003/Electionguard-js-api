/**
 * ElectionGuard Tally
 * 
 * Implements homomorphic tallying of encrypted ballots and
 * plaintext tally structures for election results.
 */

const crypto = require('crypto');
const { 
    ElementModP, 
    ElementModQ, 
    hashElems 
} = require('./group');
const { 
    ElGamalCiphertext 
} = require('./elgamal');
const {
    BallotBoxState,
    SubmittedBallot
} = require('./ballot');

/**
 * Ciphertext Tally Selection
 */
class CiphertextTallySelection {
    constructor(objectId, ciphertext) {
        this.objectId = objectId;
        this.ciphertext = ciphertext instanceof ElGamalCiphertext ? 
            ciphertext : new ElGamalCiphertext(ciphertext.alpha, ciphertext.beta);
    }
    
    /**
     * Add another selection's ciphertext (homomorphic addition)
     */
    add(other) {
        if (!(other instanceof CiphertextTallySelection)) {
            throw new Error('Can only add CiphertextTallySelection');
        }
        
        if (this.objectId !== other.objectId) {
            throw new Error('Cannot add selections with different object IDs');
        }
        
        return new CiphertextTallySelection(
            this.objectId,
            this.ciphertext.add(other.ciphertext)
        );
    }
    
    toJSON() {
        return {
            object_id: this.objectId,
            ciphertext: this.ciphertext.toJSON()
        };
    }
    
    static fromJSON(json) {
        return new CiphertextTallySelection(
            json.object_id || json.objectId,
            json.ciphertext
        );
    }
    
    toString() {
        return `CiphertextTallySelection(${this.objectId})`;
    }
}

/**
 * Plaintext Tally Selection
 */
class PlaintextTallySelection {
    constructor(objectId, tally, value = null, message = null) {
        this.objectId = objectId;
        this.tally = typeof tally === 'number' ? tally : parseInt(tally, 10);
        this.value = value;
        this.message = message;
    }
    
    toJSON() {
        return {
            object_id: this.objectId,
            tally: this.tally,
            value: this.value,
            message: this.message
        };
    }
    
    static fromJSON(json) {
        return new PlaintextTallySelection(
            json.object_id || json.objectId,
            json.tally,
            json.value,
            json.message
        );
    }
    
    toString() {
        return `PlaintextTallySelection(${this.objectId}: ${this.tally})`;
    }
}

/**
 * Ciphertext Tally Contest
 */
class CiphertextTallyContest {
    constructor(objectId, selections = []) {
        this.objectId = objectId;
        this.selections = new Map(); // selectionId -> CiphertextTallySelection
        
        if (Array.isArray(selections)) {
            selections.forEach(selection => this.addSelection(selection));
        }
    }
    
    /**
     * Add a selection to the contest
     */
    addSelection(selection) {
        if (selection instanceof CiphertextTallySelection) {
            this.selections.set(selection.objectId, selection);
        } else {
            const tallySelection = CiphertextTallySelection.fromJSON(selection);
            this.selections.set(tallySelection.objectId, tallySelection);
        }
    }
    
    /**
     * Get selection by ID
     */
    getSelection(selectionId) {
        return this.selections.get(selectionId);
    }
    
    /**
     * Add another contest's selections (homomorphic addition)
     */
    add(other) {
        if (!(other instanceof CiphertextTallyContest)) {
            throw new Error('Can only add CiphertextTallyContest');
        }
        
        if (this.objectId !== other.objectId) {
            throw new Error('Cannot add contests with different object IDs');
        }
        
        const result = new CiphertextTallyContest(this.objectId);
        
        // Add selections from both contests
        const allSelectionIds = new Set([
            ...this.selections.keys(),
            ...other.selections.keys()
        ]);
        
        for (const selectionId of allSelectionIds) {
            const thisSelection = this.selections.get(selectionId);
            const otherSelection = other.selections.get(selectionId);
            
            if (thisSelection && otherSelection) {
                result.addSelection(thisSelection.add(otherSelection));
            } else if (thisSelection) {
                result.addSelection(thisSelection);
            } else if (otherSelection) {
                result.addSelection(otherSelection);
            }
        }
        
        return result;
    }
    
    toJSON() {
        return {
            object_id: this.objectId,
            selections: Array.from(this.selections.values()).map(sel => sel.toJSON())
        };
    }
    
    static fromJSON(json) {
        const contest = new CiphertextTallyContest(json.object_id || json.objectId);
        
        if (json.selections) {
            json.selections.forEach(selection => {
                contest.addSelection(CiphertextTallySelection.fromJSON(selection));
            });
        }
        
        return contest;
    }
    
    toString() {
        return `CiphertextTallyContest(${this.objectId}, ${this.selections.size} selections)`;
    }
}

/**
 * Plaintext Tally Contest
 */
class PlaintextTallyContest {
    constructor(objectId, selections = []) {
        this.objectId = objectId;
        this.selections = new Map(); // selectionId -> PlaintextTallySelection
        
        if (Array.isArray(selections)) {
            selections.forEach(selection => this.addSelection(selection));
        }
    }
    
    /**
     * Add a selection to the contest
     */
    addSelection(selection) {
        if (selection instanceof PlaintextTallySelection) {
            this.selections.set(selection.objectId, selection);
        } else {
            const tallySelection = PlaintextTallySelection.fromJSON(selection);
            this.selections.set(tallySelection.objectId, tallySelection);
        }
    }
    
    /**
     * Get selection by ID
     */
    getSelection(selectionId) {
        return this.selections.get(selectionId);
    }
    
    /**
     * Get total votes in this contest
     */
    getTotalVotes() {
        return Array.from(this.selections.values())
            .reduce((total, selection) => total + selection.tally, 0);
    }
    
    toJSON() {
        return {
            object_id: this.objectId,
            selections: Array.from(this.selections.values()).map(sel => sel.toJSON())
        };
    }
    
    static fromJSON(json) {
        const contest = new PlaintextTallyContest(json.object_id || json.objectId);
        
        if (json.selections) {
            json.selections.forEach(selection => {
                contest.addSelection(PlaintextTallySelection.fromJSON(selection));
            });
        }
        
        return contest;
    }
    
    toString() {
        return `PlaintextTallyContest(${this.objectId}, ${this.selections.size} selections, ${this.getTotalVotes()} total votes)`;
    }
}

/**
 * Ciphertext Tally
 */
class CiphertextTally {
    constructor(objectId, contests = []) {
        this.objectId = objectId;
        this.contests = new Map(); // contestId -> CiphertextTallyContest
        
        if (Array.isArray(contests)) {
            contests.forEach(contest => this.addContest(contest));
        }
    }
    
    /**
     * Add a contest to the tally
     */
    addContest(contest) {
        if (contest instanceof CiphertextTallyContest) {
            this.contests.set(contest.objectId, contest);
        } else {
            const tallyContest = CiphertextTallyContest.fromJSON(contest);
            this.contests.set(tallyContest.objectId, tallyContest);
        }
    }
    
    /**
     * Get contest by ID
     */
    getContest(contestId) {
        return this.contests.get(contestId);
    }
    
    /**
     * Add another tally's contests (homomorphic addition)
     */
    add(other) {
        if (!(other instanceof CiphertextTally)) {
            throw new Error('Can only add CiphertextTally');
        }
        
        const result = new CiphertextTally(this.objectId);
        
        // Add contests from both tallies
        const allContestIds = new Set([
            ...this.contests.keys(),
            ...other.contests.keys()
        ]);
        
        for (const contestId of allContestIds) {
            const thisContest = this.contests.get(contestId);
            const otherContest = other.contests.get(contestId);
            
            if (thisContest && otherContest) {
                result.addContest(thisContest.add(otherContest));
            } else if (thisContest) {
                result.addContest(thisContest);
            } else if (otherContest) {
                result.addContest(otherContest);
            }
        }
        
        return result;
    }
    
    toJSON() {
        return {
            object_id: this.objectId,
            contests: Array.from(this.contests.values()).map(contest => contest.toJSON())
        };
    }
    
    static fromJSON(json) {
        const tally = new CiphertextTally(json.object_id || json.objectId);
        
        if (json.contests) {
            json.contests.forEach(contest => {
                tally.addContest(CiphertextTallyContest.fromJSON(contest));
            });
        }
        
        return tally;
    }
    
    toString() {
        return `CiphertextTally(${this.objectId}, ${this.contests.size} contests)`;
    }
}

/**
 * Plaintext Tally
 */
class PlaintextTally {
    constructor(objectId, contests = []) {
        this.objectId = objectId;
        this.contests = new Map(); // contestId -> PlaintextTallyContest
        
        if (Array.isArray(contests)) {
            contests.forEach(contest => this.addContest(contest));
        }
    }
    
    /**
     * Add a contest to the tally
     */
    addContest(contest) {
        if (contest instanceof PlaintextTallyContest) {
            this.contests.set(contest.objectId, contest);
        } else {
            const tallyContest = PlaintextTallyContest.fromJSON(contest);
            this.contests.set(tallyContest.objectId, tallyContest);
        }
    }
    
    /**
     * Get contest by ID
     */
    getContest(contestId) {
        return this.contests.get(contestId);
    }
    
    /**
     * Get total votes across all contests
     */
    getTotalVotes() {
        return Array.from(this.contests.values())
            .reduce((total, contest) => total + contest.getTotalVotes(), 0);
    }
    
    toJSON() {
        return {
            object_id: this.objectId,
            contests: Array.from(this.contests.values()).map(contest => contest.toJSON())
        };
    }
    
    static fromJSON(json) {
        const tally = new PlaintextTally(json.object_id || json.objectId);
        
        if (json.contests) {
            json.contests.forEach(contest => {
                tally.addContest(PlaintextTallyContest.fromJSON(contest));
            });
        }
        
        return tally;
    }
    
    toString() {
        return `PlaintextTally(${this.objectId}, ${this.contests.size} contests, ${this.getTotalVotes()} total votes)`;
    }
}

/**
 * Tally encrypted ballots using homomorphic addition
 */
function tallyBallots(submittedBallots, manifest, context = null) {
    if (!Array.isArray(submittedBallots)) {
        throw new Error('submittedBallots must be an array');
    }
    
    // Filter for cast ballots only
    const castBallots = submittedBallots.filter(submitted => {
        return submitted.isCast && submitted.isCast() || 
               submitted.state === BallotBoxState.CAST;
    });
    
    if (castBallots.length === 0) {
        throw new Error('No cast ballots to tally');
    }
    
    // Initialize tally with first ballot
    let tally = null;
    
    for (const submittedBallot of castBallots) {
        const ballot = submittedBallot.ballot || submittedBallot;
        const ballotTally = createBallotTally(ballot);
        
        if (!tally) {
            tally = ballotTally;
        } else {
            tally = tally.add(ballotTally);
        }
    }
    
    return tally;
}

/**
 * Create a ciphertext tally from a single ballot
 */
function createBallotTally(ballot) {
    const tally = new CiphertextTally(`tally-${ballot.ballotId}`);
    
    for (const contest of ballot.contests) {
        const contestTally = new CiphertextTallyContest(contest.objectId);
        
        for (const selection of contest.ballotSelections) {
            const selectionTally = new CiphertextTallySelection(
                selection.objectId,
                selection.ciphertext
            );
            contestTally.addSelection(selectionTally);
        }
        
        tally.addContest(contestTally);
    }
    
    return tally;
}

/**
 * Decrypt a ciphertext tally to produce plaintext results
 */
function decryptTally(ciphertextTally, guardians, manifest = null, context = null) {
    const plaintextTally = new PlaintextTally(ciphertextTally.objectId);
    
    for (const [contestId, ciphertextContest] of ciphertextTally.contests) {
        const plaintextContest = new PlaintextTallyContest(contestId);
        
        for (const [selectionId, ciphertextSelection] of ciphertextContest.selections) {
            // For each selection, we would need to perform threshold decryption
            // This is a simplified version - in practice would use DecryptionMediator
            let decryptedValue = 0;
            
            try {
                // In a real implementation, this would use proper threshold decryption
                // with partial decryption shares from guardians
                decryptedValue = simulateDecryption(ciphertextSelection.ciphertext, guardians);
            } catch (error) {
                console.warn(`Failed to decrypt selection ${selectionId}:`, error.message);
            }
            
            const plaintextSelection = new PlaintextTallySelection(
                selectionId,
                decryptedValue,
                decryptedValue,
                `Decrypted value for ${selectionId}`
            );
            
            plaintextContest.addSelection(plaintextSelection);
        }
        
        plaintextTally.addContest(plaintextContest);
    }
    
    return plaintextTally;
}

/**
 * Simulate decryption (placeholder for actual threshold decryption)
 */
function simulateDecryption(ciphertext, guardians) {
    // This is a placeholder - in reality would use proper threshold decryption
    // with partial shares from guardians and Lagrange interpolation
    
    if (!guardians || guardians.length === 0) {
        return 0;
    }
    
    // For demo purposes, return a random small value
    // In practice, this would be the result of combining partial decryption shares
    return Math.floor(Math.random() * 100);
}

/**
 * Verify tally consistency
 */
function verifyTally(ciphertextTally, submittedBallots, manifest = null) {
    try {
        // Verify that tally matches sum of individual ballots
        const recomputedTally = tallyBallots(submittedBallots, manifest);
        
        // Compare each contest and selection
        for (const [contestId, contest] of ciphertextTally.contests) {
            const recomputedContest = recomputedTally.getContest(contestId);
            if (!recomputedContest) {
                return false;
            }
            
            for (const [selectionId, selection] of contest.selections) {
                const recomputedSelection = recomputedContest.getSelection(selectionId);
                if (!recomputedSelection) {
                    return false;
                }
                
                // Compare ciphertexts
                if (!selection.ciphertext.equals(recomputedSelection.ciphertext)) {
                    return false;
                }
            }
        }
        
        return true;
    } catch (error) {
        console.error('Tally verification error:', error);
        return false;
    }
}

/**
 * Generate tally hash for verification
 */
function generateTallyHash(tally, context = null) {
    const elements = [tally.objectId];
    
    // Sort contests for deterministic hash
    const sortedContestIds = Array.from(tally.contests.keys()).sort();
    
    for (const contestId of sortedContestIds) {
        const contest = tally.contests.get(contestId);
        elements.push(contestId);
        
        // Sort selections for deterministic hash
        const sortedSelectionIds = Array.from(contest.selections.keys()).sort();
        
        for (const selectionId of sortedSelectionIds) {
            const selection = contest.selections.get(selectionId);
            elements.push(selectionId);
            elements.push(selection.ciphertext.alpha.toHex());
            elements.push(selection.ciphertext.beta.toHex());
        }
    }
    
    if (context) {
        elements.push(JSON.stringify(context));
    }
    
    return hashElems(...elements);
}

module.exports = {
    CiphertextTallySelection,
    PlaintextTallySelection,
    CiphertextTallyContest,
    PlaintextTallyContest,
    CiphertextTally,
    PlaintextTally,
    tallyBallots,
    createBallotTally,
    decryptTally,
    verifyTally,
    generateTallyHash
};
