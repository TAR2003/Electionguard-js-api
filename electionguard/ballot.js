/**
 * ElectionGuard Ballot Structures
 * 
 * Implements ballot data structures for plaintext and encrypted ballots,
 * ballot boxes, and ballot state management.
 */

const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { ElGamalCiphertext } = require('./elgamal');
const { ElementModP, ElementModQ, hashElems } = require('./group');

/**
 * Ballot Box States
 */
const BallotBoxState = {
    UNKNOWN: 'unknown',
    CAST: 'cast',
    SPOILED: 'spoiled',
    CHALLENGED: 'challenged'
};

/**
 * Plaintext Ballot Selection
 */
class PlaintextBallotSelection {
    constructor(objectId, vote, isPlaceholderSelection = false) {
        this.objectId = objectId;
        this.vote = vote; // 0 or 1 for single selection, or integer for multiple selection
        this.isPlaceholderSelection = isPlaceholderSelection;
    }
    
    isValid() {
        return typeof this.vote === 'number' && this.vote >= 0;
    }
    
    toJSON() {
        return {
            objectId: this.objectId,
            vote: this.vote,
            isPlaceholderSelection: this.isPlaceholderSelection
        };
    }
    
    static fromJSON(json) {
        return new PlaintextBallotSelection(
            json.objectId || json.object_id,
            json.vote,
            json.isPlaceholderSelection || json.is_placeholder_selection || false
        );
    }
    
    toString() {
        return `PlaintextBallotSelection(${this.objectId}: ${this.vote})`;
    }
}

/**
 * Ciphertext Ballot Selection
 */
class CiphertextBallotSelection {
    constructor(objectId, ciphertext, proof = null, isPlaceholderSelection = false) {
        this.objectId = objectId;
        this.ciphertext = ciphertext instanceof ElGamalCiphertext ? ciphertext : new ElGamalCiphertext(ciphertext.alpha, ciphertext.beta);
        this.proof = proof;
        this.isPlaceholderSelection = isPlaceholderSelection;
    }
    
    isValid() {
        return this.ciphertext && this.ciphertext.isValid();
    }
    
    toJSON() {
        return {
            objectId: this.objectId,
            ciphertext: this.ciphertext.toJSON(),
            proof: this.proof,
            isPlaceholderSelection: this.isPlaceholderSelection
        };
    }
    
    static fromJSON(json) {
        return new CiphertextBallotSelection(
            json.objectId || json.object_id,
            json.ciphertext,
            json.proof,
            json.isPlaceholderSelection || json.is_placeholder_selection || false
        );
    }
    
    toString() {
        return `CiphertextBallotSelection(${this.objectId})`;
    }
}

/**
 * Plaintext Ballot Contest
 */
class PlaintextBallotContest {
    constructor(objectId, ballotSelections) {
        this.objectId = objectId;
        this.ballotSelections = ballotSelections || [];
    }
    
    addSelection(selection) {
        if (selection instanceof PlaintextBallotSelection) {
            this.ballotSelections.push(selection);
        } else {
            throw new Error('Selection must be PlaintextBallotSelection');
        }
    }
    
    isValid(maxSelections = null) {
        const totalVotes = this.ballotSelections.reduce((sum, sel) => sum + sel.vote, 0);
        return maxSelections === null || totalVotes <= maxSelections;
    }
    
    toJSON() {
        return {
            objectId: this.objectId,
            ballotSelections: this.ballotSelections.map(sel => sel.toJSON())
        };
    }
    
    static fromJSON(json) {
        const contest = new PlaintextBallotContest(json.objectId || json.object_id);
        contest.ballotSelections = (json.ballotSelections || json.ballot_selections || [])
            .map(sel => PlaintextBallotSelection.fromJSON(sel));
        return contest;
    }
    
    toString() {
        return `PlaintextBallotContest(${this.objectId}, ${this.ballotSelections.length} selections)`;
    }
}

/**
 * Ciphertext Ballot Contest
 */
class CiphertextBallotContest {
    constructor(objectId, ballotSelections, proof = null) {
        this.objectId = objectId;
        this.ballotSelections = ballotSelections || [];
        this.proof = proof;
        this.ciphertextAccumulation = null; // Will be computed later
    }
    
    addSelection(selection) {
        if (selection instanceof CiphertextBallotSelection) {
            this.ballotSelections.push(selection);
        } else {
            throw new Error('Selection must be CiphertextBallotSelection');
        }
    }
    
    /**
     * Compute the accumulation of all selections in this contest
     */
    computeAccumulation() {
        if (this.ballotSelections.length === 0) {
            return null;
        }
        
        let accumulation = this.ballotSelections[0].ciphertext;
        for (let i = 1; i < this.ballotSelections.length; i++) {
            accumulation = accumulation.add(this.ballotSelections[i].ciphertext);
        }
        
        this.ciphertextAccumulation = accumulation;
        return accumulation;
    }
    
    isValid() {
        return this.ballotSelections.every(sel => sel.isValid());
    }
    
    toJSON() {
        return {
            objectId: this.objectId,
            ballotSelections: this.ballotSelections.map(sel => sel.toJSON()),
            proof: this.proof,
            ciphertextAccumulation: this.ciphertextAccumulation ? this.ciphertextAccumulation.toJSON() : null
        };
    }
    
    static fromJSON(json) {
        const contest = new CiphertextBallotContest(json.objectId || json.object_id);
        contest.ballotSelections = (json.ballotSelections || json.ballot_selections || [])
            .map(sel => CiphertextBallotSelection.fromJSON(sel));
        contest.proof = json.proof;
        if (json.ciphertextAccumulation || json.ciphertext_accumulation) {
            contest.ciphertextAccumulation = new ElGamalCiphertext(
                json.ciphertextAccumulation || json.ciphertext_accumulation
            );
        }
        return contest;
    }
    
    toString() {
        return `CiphertextBallotContest(${this.objectId}, ${this.ballotSelections.length} selections)`;
    }
}

/**
 * Plaintext Ballot
 */
class PlaintextBallot {
    constructor(ballotId, ballotStyleId, contests = []) {
        this.ballotId = ballotId || uuidv4();
        this.ballotStyleId = ballotStyleId || 'ballot-style-1';
        this.contests = contests;
    }
    
    addContest(contest) {
        if (contest instanceof PlaintextBallotContest) {
            this.contests.push(contest);
        } else {
            throw new Error('Contest must be PlaintextBallotContest');
        }
    }
    
    isValid() {
        return this.contests.every(contest => contest.isValid());
    }
    
    toJSON() {
        return {
            ballotId: this.ballotId,
            ballotStyleId: this.ballotStyleId,
            contests: this.contests.map(contest => contest.toJSON())
        };
    }
    
    static fromJSON(json) {
        const ballot = new PlaintextBallot(
            json.ballotId || json.ballot_id,
            json.ballotStyleId || json.ballot_style_id
        );
        ballot.contests = (json.contests || []).map(contest => PlaintextBallotContest.fromJSON(contest));
        return ballot;
    }
    
    toString() {
        return `PlaintextBallot(${this.ballotId}, ${this.contests.length} contests)`;
    }
}

/**
 * Ciphertext Ballot
 */
class CiphertextBallot {
    constructor(ballotId, ballotStyleId, manifestHash, contests = []) {
        this.ballotId = ballotId || uuidv4();
        this.ballotStyleId = ballotStyleId || 'ballot-style-1';
        this.manifestHash = manifestHash;
        this.contests = contests;
        this.ballotCodeSeed = null;
        this.ballotCode = null;
        this.timestamp = Date.now();
        this.cryptoHash = null;
    }
    
    addContest(contest) {
        if (contest instanceof CiphertextBallotContest) {
            this.contests.push(contest);
        } else {
            throw new Error('Contest must be CiphertextBallotContest');
        }
    }
    
    /**
     * Generate ballot code from seed
     */
    generateBallotCode(seed = null) {
        if (!seed) {
            seed = crypto.randomBytes(32);
        }
        this.ballotCodeSeed = seed;
        
        // Generate deterministic ballot code
        const hash = crypto.createHash('sha256');
        hash.update(seed);
        hash.update(this.ballotId);
        hash.update(this.ballotStyleId);
        
        this.ballotCode = hash.digest('hex').substring(0, 16).toUpperCase();
        return this.ballotCode;
    }
    
    /**
     * Compute cryptographic hash of the ballot
     */
    computeCryptoHash() {
        const elements = [
            this.ballotId,
            this.ballotStyleId,
            this.manifestHash
        ];
        
        // Add contest hashes
        for (const contest of this.contests) {
            elements.push(contest.objectId);
            for (const selection of contest.ballotSelections) {
                elements.push(selection.objectId);
                elements.push(selection.ciphertext.alpha.toHex());
                elements.push(selection.ciphertext.beta.toHex());
            }
        }
        
        this.cryptoHash = hashElems(...elements);
        return this.cryptoHash;
    }
    
    isValid() {
        return this.contests.every(contest => contest.isValid());
    }
    
    toJSON() {
        return {
            ballotId: this.ballotId,
            ballotStyleId: this.ballotStyleId,
            manifestHash: this.manifestHash,
            contests: this.contests.map(contest => contest.toJSON()),
            ballotCodeSeed: this.ballotCodeSeed ? this.ballotCodeSeed.toString('hex') : null,
            ballotCode: this.ballotCode,
            timestamp: this.timestamp,
            cryptoHash: this.cryptoHash ? this.cryptoHash.toJSON() : null
        };
    }
    
    static fromJSON(json) {
        const ballot = new CiphertextBallot(
            json.ballotId || json.ballot_id,
            json.ballotStyleId || json.ballot_style_id,
            json.manifestHash || json.manifest_hash
        );
        
        ballot.contests = (json.contests || []).map(contest => CiphertextBallotContest.fromJSON(contest));
        ballot.ballotCodeSeed = json.ballotCodeSeed ? Buffer.from(json.ballotCodeSeed, 'hex') : null;
        ballot.ballotCode = json.ballotCode || json.ballot_code;
        ballot.timestamp = json.timestamp || Date.now();
        ballot.cryptoHash = json.cryptoHash ? ElementModQ.fromJSON(json.cryptoHash) : null;
        
        return ballot;
    }
    
    toString() {
        return `CiphertextBallot(${this.ballotId}, ${this.contests.length} contests)`;
    }
}

/**
 * Submitted Ballot
 */
class SubmittedBallot {
    constructor(ballot, state = BallotBoxState.UNKNOWN) {
        if (ballot instanceof CiphertextBallot) {
            this.ballot = ballot;
        } else {
            this.ballot = CiphertextBallot.fromJSON(ballot);
        }
        this.state = state;
        this.timestamp = Date.now();
    }
    
    cast() {
        this.state = BallotBoxState.CAST;
        return this;
    }
    
    spoil() {
        this.state = BallotBoxState.SPOILED;
        return this;
    }
    
    challenge() {
        this.state = BallotBoxState.CHALLENGED;
        return this;
    }
    
    isCast() {
        return this.state === BallotBoxState.CAST;
    }
    
    isSpoiled() {
        return this.state === BallotBoxState.SPOILED;
    }
    
    isChallenged() {
        return this.state === BallotBoxState.CHALLENGED;
    }
    
    toJSON() {
        return {
            ballot: this.ballot.toJSON(),
            state: this.state,
            timestamp: this.timestamp
        };
    }
    
    static fromJSON(json) {
        return new SubmittedBallot(
            json.ballot,
            json.state || BallotBoxState.UNKNOWN
        );
    }
    
    toString() {
        return `SubmittedBallot(${this.ballot.ballotId}, ${this.state})`;
    }
}

/**
 * Ballot Box
 */
class BallotBox {
    constructor() {
        this.ballots = new Map(); // ballotId -> SubmittedBallot
        this.cast = new Map();
        this.spoiled = new Map();
        this.challenged = new Map();
    }
    
    /**
     * Submit a ballot to the ballot box
     */
    submit(ballot, state = BallotBoxState.CAST) {
        const submittedBallot = new SubmittedBallot(ballot, state);
        this.ballots.set(ballot.ballotId, submittedBallot);
        
        // Update state-specific collections
        this.updateStateCollections(submittedBallot);
        
        return submittedBallot;
    }
    
    /**
     * Cast a ballot
     */
    cast(ballotId) {
        const submitted = this.ballots.get(ballotId);
        if (!submitted) {
            throw new Error(`Ballot ${ballotId} not found`);
        }
        
        submitted.cast();
        this.updateStateCollections(submitted);
        return submitted;
    }
    
    /**
     * Spoil a ballot
     */
    spoil(ballotId) {
        const submitted = this.ballots.get(ballotId);
        if (!submitted) {
            throw new Error(`Ballot ${ballotId} not found`);
        }
        
        submitted.spoil();
        this.updateStateCollections(submitted);
        return submitted;
    }
    
    /**
     * Challenge a ballot
     */
    challenge(ballotId) {
        const submitted = this.ballots.get(ballotId);
        if (!submitted) {
            throw new Error(`Ballot ${ballotId} not found`);
        }
        
        submitted.challenge();
        this.updateStateCollections(submitted);
        return submitted;
    }
    
    /**
     * Update state-specific collections
     */
    updateStateCollections(submittedBallot) {
        const ballotId = submittedBallot.ballot.ballotId;
        
        // Clear from all collections first
        this.cast.delete(ballotId);
        this.spoiled.delete(ballotId);
        this.challenged.delete(ballotId);
        
        // Add to appropriate collection
        switch (submittedBallot.state) {
            case BallotBoxState.CAST:
                this.cast.set(ballotId, submittedBallot);
                break;
            case BallotBoxState.SPOILED:
                this.spoiled.set(ballotId, submittedBallot);
                break;
            case BallotBoxState.CHALLENGED:
                this.challenged.set(ballotId, submittedBallot);
                break;
        }
    }
    
    /**
     * Get all cast ballots
     */
    getCastBallots() {
        return Array.from(this.cast.values());
    }
    
    /**
     * Get all spoiled ballots
     */
    getSpoiledBallots() {
        return Array.from(this.spoiled.values());
    }
    
    /**
     * Get all challenged ballots
     */
    getChallengedBallots() {
        return Array.from(this.challenged.values());
    }
    
    /**
     * Get ballot by ID
     */
    getBallot(ballotId) {
        return this.ballots.get(ballotId);
    }
    
    /**
     * Get total count
     */
    getCount() {
        return this.ballots.size;
    }
    
    toJSON() {
        return {
            ballots: Array.from(this.ballots.values()).map(b => b.toJSON()),
            cast: Array.from(this.cast.values()).map(b => b.toJSON()),
            spoiled: Array.from(this.spoiled.values()).map(b => b.toJSON()),
            challenged: Array.from(this.challenged.values()).map(b => b.toJSON())
        };
    }
    
    static fromJSON(json) {
        const ballotBox = new BallotBox();
        
        if (json.ballots) {
            json.ballots.forEach(ballotData => {
                const submitted = SubmittedBallot.fromJSON(ballotData);
                ballotBox.ballots.set(submitted.ballot.ballotId, submitted);
                ballotBox.updateStateCollections(submitted);
            });
        }
        
        return ballotBox;
    }
}

/**
 * Get ballots from ballot box in specific state
 */
function getBallots(ballotBox, state = null) {
    if (!state) {
        return Array.from(ballotBox.ballots.values());
    }
    
    switch (state) {
        case BallotBoxState.CAST:
            return ballotBox.getCastBallots();
        case BallotBoxState.SPOILED:
            return ballotBox.getSpoiledBallots();
        case BallotBoxState.CHALLENGED:
            return ballotBox.getChallengedBallots();
        default:
            return Array.from(ballotBox.ballots.values())
                .filter(b => b.state === state);
    }
}

module.exports = {
    BallotBoxState,
    PlaintextBallotSelection,
    CiphertextBallotSelection,
    PlaintextBallotContest,
    CiphertextBallotContest,
    PlaintextBallot,
    CiphertextBallot,
    SubmittedBallot,
    BallotBox,
    getBallots
};
