/**
 * ElectionGuard Election Manifest
 * 
 * Implements election description structures including candidates,
 * contests, ballot styles, and other election metadata.
 */

const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { hashElems } = require('./group');

/**
 * Election Type Enumeration
 */
const ElectionType = {
    UNKNOWN: 'unknown',
    GENERAL: 'general',
    PARTISAN_PRIMARY_CLOSED: 'partisan_primary_closed',
    PARTISAN_PRIMARY_OPEN: 'partisan_primary_open',
    PRIMARY: 'primary',
    RUNOFF: 'runoff',
    SPECIAL: 'special',
    OTHER: 'other'
};

/**
 * Vote Variation Type
 */
const VoteVariationType = {
    UNKNOWN: 'unknown',
    ONE_OF_M: 'one_of_m',      // Choose exactly one
    APPROVAL: 'approval',       // Choose any number
    BORDA: 'borda',            // Rank candidates
    CUMULATIVE: 'cumulative',   // Distribute points
    MAJORITY: 'majority',       // Majority required
    N_OF_M: 'n_of_m',          // Choose exactly N
    PLURALITY: 'plurality',     // Most votes wins
    PROPORTIONAL: 'proportional', // Proportional representation
    RANGE: 'range',            // Score voting
    RCV: 'rcv',                // Ranked choice voting
    SUPER_MAJORITY: 'super_majority', // Super majority required
    OTHER: 'other'
};

/**
 * Reporting Unit Type
 */
const ReportingUnitType = {
    BALLOT_BATCH: 'ballot-batch',
    BALLOT_STYLE_AREA: 'ballot-style-area',
    BOROUGH: 'borough',
    CITY: 'city',
    CITY_COUNCIL: 'city-council',
    COMBINED_PRECINCT: 'combined-precinct',
    CONGRESSIONAL: 'congressional',
    COUNTY: 'county',
    COUNTY_COUNCIL: 'county-council',
    DROP_BOX: 'drop-box',
    JUDICIAL: 'judicial',
    MUNICIPALITY: 'municipality',
    POLLING_PLACE: 'polling-place',
    PRECINCT: 'precinct',
    SCHOOL: 'school',
    SPECIAL: 'special',
    SPLIT_PRECINCT: 'split-precinct',
    STATE: 'state',
    STATE_HOUSE: 'state-house',
    STATE_SENATE: 'state-senate',
    TOWNSHIP: 'township',
    UTILITY: 'utility',
    VILLAGE: 'village',
    VOTE_CENTER: 'vote-center',
    WARD: 'ward',
    WATER: 'water',
    OTHER: 'other'
};

/**
 * Spec Version
 */
const SpecVersion = '1.0';

/**
 * Contact Information
 */
class ContactInformation {
    constructor(name = '', addressLine = [], email = '', phone = '') {
        this.name = name;
        this.addressLine = Array.isArray(addressLine) ? addressLine : [addressLine];
        this.email = email;
        this.phone = phone;
    }
    
    toJSON() {
        return {
            name: this.name,
            address_line: this.addressLine,
            email: this.email,
            phone: this.phone
        };
    }
    
    static fromJSON(json) {
        return new ContactInformation(
            json.name || '',
            json.address_line || json.addressLine || [],
            json.email || '',
            json.phone || ''
        );
    }
}

/**
 * Geopolitical Unit
 */
class GeopoliticalUnit {
    constructor(objectId, name, type, contactInformation = null) {
        this.objectId = objectId;
        this.name = name;
        this.type = type;
        this.contactInformation = contactInformation;
    }
    
    toJSON() {
        return {
            object_id: this.objectId,
            name: this.name,
            type: this.type,
            contact_information: this.contactInformation ? this.contactInformation.toJSON() : null
        };
    }
    
    static fromJSON(json) {
        return new GeopoliticalUnit(
            json.object_id || json.objectId,
            json.name,
            json.type,
            json.contact_information ? ContactInformation.fromJSON(json.contact_information) : null
        );
    }
    
    toString() {
        return `GeopoliticalUnit(${this.objectId}: ${this.name})`;
    }
}

/**
 * Party
 */
class Party {
    constructor(objectId, name, abbreviation = '', color = '', logoUri = '') {
        this.objectId = objectId;
        this.name = name;
        this.abbreviation = abbreviation || name.substring(0, 3).toUpperCase();
        this.color = color;
        this.logoUri = logoUri;
    }
    
    toJSON() {
        return {
            object_id: this.objectId,
            name: this.name,
            abbreviation: this.abbreviation,
            color: this.color,
            logo_uri: this.logoUri
        };
    }
    
    static fromJSON(json) {
        return new Party(
            json.object_id || json.objectId,
            json.name,
            json.abbreviation,
            json.color || '',
            json.logo_uri || json.logoUri || ''
        );
    }
    
    toString() {
        return `Party(${this.objectId}: ${this.name})`;
    }
}

/**
 * Candidate
 */
class Candidate {
    constructor(objectId, name, partyId = null, imageUri = '', isWriteIn = false) {
        this.objectId = objectId;
        this.name = name;
        this.partyId = partyId;
        this.imageUri = imageUri;
        this.isWriteIn = isWriteIn;
    }
    
    toJSON() {
        return {
            object_id: this.objectId,
            name: this.name,
            party_id: this.partyId,
            image_uri: this.imageUri,
            is_write_in: this.isWriteIn
        };
    }
    
    static fromJSON(json) {
        return new Candidate(
            json.object_id || json.objectId,
            json.name,
            json.party_id || json.partyId,
            json.image_uri || json.imageUri || '',
            json.is_write_in || json.isWriteIn || false
        );
    }
    
    toString() {
        return `Candidate(${this.objectId}: ${this.name})`;
    }
}

/**
 * Ballot Selection Description
 */
class SelectionDescription {
    constructor(objectId, candidateId, sequenceOrder) {
        this.objectId = objectId;
        this.candidateId = candidateId;
        this.sequenceOrder = sequenceOrder;
    }
    
    toJSON() {
        return {
            object_id: this.objectId,
            candidate_id: this.candidateId,
            sequence_order: this.sequenceOrder
        };
    }
    
    static fromJSON(json) {
        return new SelectionDescription(
            json.object_id || json.objectId,
            json.candidate_id || json.candidateId,
            json.sequence_order || json.sequenceOrder
        );
    }
    
    toString() {
        return `SelectionDescription(${this.objectId})`;
    }
}

/**
 * Contest Description
 */
class ContestDescription {
    constructor(objectId, electoralDistrictId, sequenceOrder, voteVariation, numberElected, name, ballotSelections = []) {
        this.objectId = objectId;
        this.electoralDistrictId = electoralDistrictId;
        this.sequenceOrder = sequenceOrder;
        this.voteVariation = voteVariation;
        this.numberElected = numberElected;
        this.name = name;
        this.ballotSelections = ballotSelections;
        this.ballotTitle = name;
        this.ballotSubtitle = '';
    }
    
    addSelection(selection) {
        if (selection instanceof SelectionDescription) {
            this.ballotSelections.push(selection);
        } else {
            // Create selection from simple object
            this.ballotSelections.push(new SelectionDescription(
                selection.object_id || selection.objectId,
                selection.candidate_id || selection.candidateId,
                selection.sequence_order || selection.sequenceOrder
            ));
        }
    }
    
    toJSON() {
        return {
            object_id: this.objectId,
            electoral_district_id: this.electoralDistrictId,
            sequence_order: this.sequenceOrder,
            vote_variation: this.voteVariation,
            number_elected: this.numberElected,
            name: this.name,
            ballot_title: this.ballotTitle,
            ballot_subtitle: this.ballotSubtitle,
            ballot_selections: this.ballotSelections.map(sel => sel.toJSON())
        };
    }
    
    static fromJSON(json) {
        const contest = new ContestDescription(
            json.object_id || json.objectId,
            json.electoral_district_id || json.electoralDistrictId,
            json.sequence_order || json.sequenceOrder,
            json.vote_variation || json.voteVariation,
            json.number_elected || json.numberElected,
            json.name
        );
        
        contest.ballotTitle = json.ballot_title || json.ballotTitle || json.name;
        contest.ballotSubtitle = json.ballot_subtitle || json.ballotSubtitle || '';
        contest.ballotSelections = (json.ballot_selections || json.ballotSelections || [])
            .map(sel => SelectionDescription.fromJSON(sel));
            
        return contest;
    }
    
    toString() {
        return `ContestDescription(${this.objectId}: ${this.name})`;
    }
}

/**
 * Ballot Style
 */
class BallotStyle {
    constructor(objectId, geopoliticalUnitIds = [], contestIds = []) {
        this.objectId = objectId;
        this.geopoliticalUnitIds = geopoliticalUnitIds;
        this.contestIds = contestIds;
    }
    
    toJSON() {
        return {
            object_id: this.objectId,
            geopolitical_unit_ids: this.geopoliticalUnitIds,
            contest_ids: this.contestIds
        };
    }
    
    static fromJSON(json) {
        return new BallotStyle(
            json.object_id || json.objectId,
            json.geopolitical_unit_ids || json.geopoliticalUnitIds || [],
            json.contest_ids || json.contestIds || []
        );
    }
    
    toString() {
        return `BallotStyle(${this.objectId})`;
    }
}

/**
 * Election Manifest
 */
class Manifest {
    constructor(electionScopeId, specVersion = SpecVersion, type = ElectionType.GENERAL, startDate = null, endDate = null) {
        this.electionScopeId = electionScopeId;
        this.specVersion = specVersion;
        this.type = type;
        this.startDate = startDate || new Date().toISOString().split('T')[0];
        this.endDate = endDate || new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString().split('T')[0];
        this.geopoliticalUnits = [];
        this.parties = [];
        this.candidates = [];
        this.contests = [];
        this.ballotStyles = [];
        this.name = '';
        this.contactInformation = null;
    }
    
    addGeopoliticalUnit(unit) {
        if (unit instanceof GeopoliticalUnit) {
            this.geopoliticalUnits.push(unit);
        } else {
            this.geopoliticalUnits.push(GeopoliticalUnit.fromJSON(unit));
        }
    }
    
    addParty(party) {
        if (party instanceof Party) {
            this.parties.push(party);
        } else {
            this.parties.push(Party.fromJSON(party));
        }
    }
    
    addCandidate(candidate) {
        if (candidate instanceof Candidate) {
            this.candidates.push(candidate);
        } else {
            this.candidates.push(Candidate.fromJSON(candidate));
        }
    }
    
    addContest(contest) {
        if (contest instanceof ContestDescription) {
            this.contests.push(contest);
        } else {
            this.contests.push(ContestDescription.fromJSON(contest));
        }
    }
    
    addBallotStyle(ballotStyle) {
        if (ballotStyle instanceof BallotStyle) {
            this.ballotStyles.push(ballotStyle);
        } else {
            this.ballotStyles.push(BallotStyle.fromJSON(ballotStyle));
        }
    }
    
    /**
     * Compute cryptographic hash of the manifest
     */
    computeHash() {
        const elements = [
            this.electionScopeId,
            this.specVersion,
            this.type,
            this.startDate,
            this.endDate,
            this.name
        ];
        
        // Add geopolitical units
        for (const unit of this.geopoliticalUnits) {
            elements.push(unit.objectId, unit.name, unit.type);
        }
        
        // Add parties
        for (const party of this.parties) {
            elements.push(party.objectId, party.name, party.abbreviation);
        }
        
        // Add candidates
        for (const candidate of this.candidates) {
            elements.push(candidate.objectId, candidate.name, candidate.partyId || '');
        }
        
        // Add contests
        for (const contest of this.contests) {
            elements.push(contest.objectId, contest.name, contest.voteVariation);
            for (const selection of contest.ballotSelections) {
                elements.push(selection.objectId, selection.candidateId);
            }
        }
        
        // Add ballot styles
        for (const style of this.ballotStyles) {
            elements.push(style.objectId);
            elements.push(...style.geopoliticalUnitIds);
            elements.push(...style.contestIds);
        }
        
        return hashElems(...elements);
    }
    
    toJSON() {
        return {
            election_scope_id: this.electionScopeId,
            spec_version: this.specVersion,
            type: this.type,
            start_date: this.startDate,
            end_date: this.endDate,
            name: this.name,
            contact_information: this.contactInformation ? this.contactInformation.toJSON() : null,
            geopolitical_units: this.geopoliticalUnits.map(unit => unit.toJSON()),
            parties: this.parties.map(party => party.toJSON()),
            candidates: this.candidates.map(candidate => candidate.toJSON()),
            contests: this.contests.map(contest => contest.toJSON()),
            ballot_styles: this.ballotStyles.map(style => style.toJSON())
        };
    }
    
    static fromJSON(json) {
        const manifest = new Manifest(
            json.election_scope_id || json.electionScopeId,
            json.spec_version || json.specVersion,
            json.type,
            json.start_date || json.startDate,
            json.end_date || json.endDate
        );
        
        manifest.name = json.name || '';
        manifest.contactInformation = json.contact_information ? 
            ContactInformation.fromJSON(json.contact_information) : null;
            
        manifest.geopoliticalUnits = (json.geopolitical_units || json.geopoliticalUnits || [])
            .map(unit => GeopoliticalUnit.fromJSON(unit));
            
        manifest.parties = (json.parties || [])
            .map(party => Party.fromJSON(party));
            
        manifest.candidates = (json.candidates || [])
            .map(candidate => Candidate.fromJSON(candidate));
            
        manifest.contests = (json.contests || [])
            .map(contest => ContestDescription.fromJSON(contest));
            
        manifest.ballotStyles = (json.ballot_styles || json.ballotStyles || [])
            .map(style => BallotStyle.fromJSON(style));
            
        return manifest;
    }
    
    toString() {
        return `Manifest(${this.electionScopeId}: ${this.name})`;
    }
}

/**
 * Internal Manifest (optimized for cryptographic operations)
 */
class InternalManifest {
    constructor(manifest) {
        if (manifest instanceof Manifest) {
            this.manifest = manifest;
        } else {
            this.manifest = Manifest.fromJSON(manifest);
        }
        
        this.manifestHash = this.manifest.computeHash();
        this.geopoliticalUnitMap = new Map();
        this.contestMap = new Map();
        this.candidateMap = new Map();
        this.ballotStyleMap = new Map();
        
        this.buildMaps();
    }
    
    buildMaps() {
        // Build lookup maps for efficient access
        this.manifest.geopoliticalUnits.forEach(unit => {
            this.geopoliticalUnitMap.set(unit.objectId, unit);
        });
        
        this.manifest.contests.forEach(contest => {
            this.contestMap.set(contest.objectId, contest);
        });
        
        this.manifest.candidates.forEach(candidate => {
            this.candidateMap.set(candidate.objectId, candidate);
        });
        
        this.manifest.ballotStyles.forEach(style => {
            this.ballotStyleMap.set(style.objectId, style);
        });
    }
    
    getContest(contestId) {
        return this.contestMap.get(contestId);
    }
    
    getCandidate(candidateId) {
        return this.candidateMap.get(candidateId);
    }
    
    getBallotStyle(styleId) {
        return this.ballotStyleMap.get(styleId);
    }
    
    getGeopoliticalUnit(unitId) {
        return this.geopoliticalUnitMap.get(unitId);
    }
    
    toJSON() {
        return {
            manifest: this.manifest.toJSON(),
            manifest_hash: this.manifestHash.toJSON()
        };
    }
    
    static fromJSON(json) {
        return new InternalManifest(json.manifest);
    }
}

module.exports = {
    ElectionType,
    VoteVariationType,
    ReportingUnitType,
    SpecVersion,
    ContactInformation,
    GeopoliticalUnit,
    Party,
    Candidate,
    SelectionDescription,
    ContestDescription,
    BallotStyle,
    Manifest,
    InternalManifest
};
