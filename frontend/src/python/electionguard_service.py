"""
ElectionGuard service for creating encrypted ballots.
This module contains simplified versions of the ElectionGuard functions
optimized for running in Pyodide.
"""

import json
import hashlib
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict


@dataclass
class PlaintextBallotSelection:
    object_id: str
    vote: int
    is_placeholder_selection: bool = False


@dataclass 
class PlaintextBallotContest:
    object_id: str
    ballot_selections: List[PlaintextBallotSelection]


@dataclass
class PlaintextBallot:
    object_id: str
    style_id: str
    contests: List[PlaintextBallotContest]


@dataclass
class GeopoliticalUnit:
    object_id: str
    name: str
    type: str = "county"
    contact_information: Optional[str] = None


@dataclass
class Party:
    object_id: str
    name: str
    abbreviation: str
    color: Optional[str] = None
    logo_uri: Optional[str] = None


@dataclass
class Candidate:
    object_id: str
    name: str
    party_id: str


@dataclass
class SelectionDescription:
    object_id: str
    candidate_id: str
    sequence_order: int


@dataclass
class Contest:
    object_id: str
    sequence_order: int
    electoral_district_id: str
    vote_variation: str
    name: str
    ballot_selections: List[SelectionDescription]
    ballot_title: Optional[str] = None
    ballot_subtitle: Optional[str] = None
    votes_allowed: int = 1
    number_elected: int = 1


@dataclass
class BallotStyle:
    object_id: str
    geopolitical_unit_ids: List[str]
    party_ids: Optional[List[str]] = None
    image_uri: Optional[str] = None


@dataclass
class Manifest:
    election_scope_id: str
    spec_version: str
    type: str
    start_date: datetime
    end_date: datetime
    geopolitical_units: List[GeopoliticalUnit]
    parties: List[Party]
    candidates: List[Candidate]
    contests: List[Contest]
    ballot_styles: List[BallotStyle]
    name: str
    contact_information: Optional[str] = None


def create_election_manifest(party_names: List[str], candidate_names: List[str]) -> Manifest:
    """Create a complete election manifest programmatically."""
    # Create geopolitical unit
    geopolitical_unit = GeopoliticalUnit(
        object_id="county-1",
        name="County 1",
        type="county",
        contact_information=None,
    )

    # Create ballot style
    ballot_style = BallotStyle(
        object_id="ballot-style-1",
        geopolitical_unit_ids=["county-1"],
        party_ids=None,
        image_uri=None,
    )
    
    parties: List[Party] = []
    for i in range(len(party_names)):
        parties.append(
            Party(
                object_id=f"party-{i+1}",
                name=party_names[i],
                abbreviation=party_names[i],
                color=None,
                logo_uri=None,
            )
        )

    candidates: List[Candidate] = []
    for i in range(len(candidate_names)):
        candidates.append(
            Candidate(
                object_id=f"candidate-{i+1}",
                name=candidate_names[i],
                party_id=f"party-{i+1}",
            )
        )
   
    ballot_selections: List[SelectionDescription] = []
    for i in range(len(candidate_names)):
        ballot_selections.append(
            SelectionDescription(
                object_id=f"{candidate_names[i]}",
                candidate_id=f"{candidate_names[i]}",
                sequence_order=i,
            )
        )

    contests: List[Contest] = [
        Contest(
            object_id="contest-1",
            sequence_order=0,
            electoral_district_id="county-1",
            vote_variation="one_of_m",
            name="County Executive",
            ballot_selections=ballot_selections,
            ballot_title=None,
            ballot_subtitle=None,
            votes_allowed=1,
            number_elected=1,
        ),
    ]
    
    start_date = datetime(2025, 1, 1)
    end_date = datetime(2025, 1, 1)
    
    manifest = Manifest(
        election_scope_id=f"election-1",
        spec_version="1.0",
        type="general",
        start_date=start_date,
        end_date=end_date,
        geopolitical_units=[geopolitical_unit],
        parties=parties,
        candidates=candidates,
        contests=contests,
        ballot_styles=[ballot_style],
        name="Test Election",
        contact_information=None,
    )
    
    return manifest


def create_plaintext_ballot(party_names: List[str], candidate_names: List[str], candidate_name: str, ballot_id: str) -> PlaintextBallot:
    """Create a single plaintext ballot for a specific candidate."""
    manifest = create_election_manifest(party_names, candidate_names)
    
    # Get ballot style
    ballot_style = manifest.ballot_styles[0]
    
    selection = None
    contest = manifest.contests[0]
    for option in contest.ballot_selections:
        if option.candidate_id == candidate_name:
            selection = option
            break
    
    if not selection:
        raise ValueError(f"Candidate {candidate_name} not found in manifest")
    
    ballot_contests = []
    for contest in manifest.contests:
        selections = []
        for option in contest.ballot_selections:
            vote = 1 if option.object_id == selection.object_id else 0
            selections.append(
                PlaintextBallotSelection(
                    object_id=option.object_id,
                    vote=vote,
                    is_placeholder_selection=False,
                )
            )
        ballot_contests.append(
            PlaintextBallotContest(
                object_id=contest.object_id,
                ballot_selections=selections
            )
        )
    
    return PlaintextBallot(
        object_id=ballot_id,
        style_id=ballot_style.object_id,
        contests=ballot_contests,
    )


def generate_ballot_hash(encrypted_ballot: Dict[str, Any]) -> str:
    """Generate a hash for the encrypted ballot."""
    ballot_str = json.dumps(encrypted_ballot, sort_keys=True)
    return hashlib.sha256(ballot_str.encode()).hexdigest()


def simulate_encryption(plaintext_ballot: PlaintextBallot, joint_public_key: int, commitment_hash: int) -> Dict[str, Any]:
    """
    Simulate ballot encryption for demonstration purposes.
    In a real implementation, this would use proper ElGamal encryption.
    """
    # Convert plaintext ballot to dict for easier manipulation
    ballot_dict = asdict(plaintext_ballot)
    
    # Simulate encryption by adding encrypted fields
    encrypted_ballot = {
        "object_id": ballot_dict["object_id"],
        "style_id": ballot_dict["style_id"],
        "manifest_hash": str(commitment_hash),
        "code_seed": str(hash(f"{ballot_dict['object_id']}{joint_public_key}")),
        "contests": []
    }
    
    for contest in ballot_dict["contests"]:
        encrypted_contest = {
            "object_id": contest["object_id"],
            "sequence_order": 0,
            "description_hash": hashlib.sha256(contest["object_id"].encode()).hexdigest(),
            "ballot_selections": []
        }
        
        for selection in contest["ballot_selections"]:
            # Simulate ElGamal encryption
            encrypted_selection = {
                "object_id": selection["object_id"],
                "sequence_order": 0,
                "description_hash": hashlib.sha256(selection["object_id"].encode()).hexdigest(),
                "ciphertext": {
                    "pad": str(joint_public_key * selection["vote"] + hash(selection["object_id"])),
                    "data": str(joint_public_key * selection["vote"] * 2 + hash(f"{selection['object_id']}_data"))
                },
                "crypto_hash": hashlib.sha256(f"{selection['object_id']}{selection['vote']}{joint_public_key}".encode()).hexdigest(),
                "is_placeholder_selection": selection["is_placeholder_selection"]
            }
            encrypted_contest["ballot_selections"].append(encrypted_selection)
        
        encrypted_ballot["contests"].append(encrypted_contest)
    
    return encrypted_ballot


def create_encrypted_ballot_service(
    party_names: List[str],
    candidate_names: List[str],
    candidate_name: str,
    ballot_id: str,
    joint_public_key: str,
    commitment_hash: str,
    number_of_guardians: int,
    quorum: int
) -> Dict[str, Any]:
    """
    Service function to create and encrypt a ballot.
    Simplified version for Pyodide implementation.
    """
    try:
        # Convert string inputs to integers for internal processing
        joint_public_key_int = int(joint_public_key)
        commitment_hash_int = int(commitment_hash)
        
        # Create plaintext ballot
        ballot = create_plaintext_ballot(party_names, candidate_names, candidate_name, ballot_id)
        
        # Simulate ballot encryption
        encrypted_ballot = simulate_encryption(ballot, joint_public_key_int, commitment_hash_int)
        
        # Generate ballot hash
        ballot_hash = generate_ballot_hash(encrypted_ballot)
        
        return {
            'encrypted_ballot': encrypted_ballot,
            'ballot_hash': ballot_hash,
            'status': 'success',
            'plaintext_ballot': asdict(ballot)  # Include for debugging
        }
    
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


# Main function to be called from JavaScript
def process_ballot_request(json_input: str) -> str:
    """
    Main entry point for processing ballot requests from the frontend.
    """
    try:
        # Parse JSON input
        data = json.loads(json_input)
        
        # Extract parameters
        party_names = data.get('party_names', [])
        candidate_names = data.get('candidate_names', [])
        candidate_name = data.get('candidate_name', '')
        ballot_id = data.get('ballot_id', str(uuid.uuid4()))
        joint_public_key = data.get('joint_public_key', '12345')
        commitment_hash = data.get('commitment_hash', '67890')
        number_of_guardians = data.get('number_of_guardians', 3)
        quorum = data.get('quorum', 2)
        
        # Validate required parameters
        if not party_names or not candidate_names or not candidate_name:
            raise ValueError("Missing required parameters: party_names, candidate_names, or candidate_name")
        
        if candidate_name not in candidate_names:
            raise ValueError(f"Candidate '{candidate_name}' not found in candidate list")
        
        # Process the ballot
        result = create_encrypted_ballot_service(
            party_names=party_names,
            candidate_names=candidate_names,
            candidate_name=candidate_name,
            ballot_id=ballot_id,
            joint_public_key=joint_public_key,
            commitment_hash=commitment_hash,
            number_of_guardians=number_of_guardians,
            quorum=quorum
        )
        
        return json.dumps(result)
        
    except Exception as e:
        error_result = {
            'status': 'error',
            'error': str(e)
        }
        return json.dumps(error_result)
