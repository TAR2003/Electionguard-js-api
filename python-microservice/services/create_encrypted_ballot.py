"""
Service for creating encrypted ballots.
"""

#!/usr/bin/env python

from flask import Flask, request, jsonify
from typing import Dict, List, Optional, Tuple, Any
import random
from datetime import datetime
import uuid
from collections import defaultdict
import hashlib
import json
from electionguard.ballot import (
    BallotBoxState,
    CiphertextBallot,
    PlaintextBallot,
    PlaintextBallotSelection,
    PlaintextBallotContest,
    SubmittedBallot,
)
from electionguard.serialize import to_raw, from_raw
from electionguard.constants import get_constants
from electionguard.data_store import DataStore
from electionguard.decryption_mediator import DecryptionMediator
from electionguard.election import CiphertextElectionContext
from electionguard.election_polynomial import (
    LagrangeCoefficientsRecord,
    ElectionPolynomial
)
from electionguard.encrypt import EncryptionDevice, EncryptionMediator
from electionguard.guardian import Guardian
from electionguard.key_ceremony_mediator import KeyCeremonyMediator
from electionguard.key_ceremony import ElectionKeyPair, ElectionPublicKey
from electionguard.ballot_box import BallotBox, get_ballots
from electionguard.elgamal import ElGamalPublicKey, ElGamalSecretKey, ElGamalCiphertext
from electionguard.group import ElementModQ, ElementModP, g_pow_p, int_to_p, int_to_q
from electionguard.manifest import (
    Manifest,
    InternalManifest,
    GeopoliticalUnit,
    Party,
    Candidate,
    ContestDescription as Contest,
    SelectionDescription,
    BallotStyle,
    ElectionType,
    VoteVariationType,
    SpecVersion,
    ContactInformation,
    ReportingUnitType
)
from electionguard_tools.helpers.election_builder import ElectionBuilder
from electionguard.tally import (
    tally_ballots,
    CiphertextTally,
    PlaintextTally,
    CiphertextTallyContest,
    CiphertextTallySelection
)
from electionguard.type import BallotId, GuardianId
from electionguard.utils import get_optional
from electionguard.election_polynomial import ElectionPolynomial, Coefficient, SecretCoefficient, PublicCommitment
from electionguard.schnorr import SchnorrProof
from electionguard.elgamal import ElGamalKeyPair, ElGamalPublicKey, ElGamalSecretKey
from electionguard.hash import hash_elems
from electionguard.decryption_share import DecryptionShare, CompensatedDecryptionShare
from electionguard.decryption import (
    compute_decryption_share, 
    compute_decryption_share_for_ballot,
    compute_compensated_decryption_share,
    compute_compensated_decryption_share_for_ballot,
    decrypt_backup,
    compute_lagrange_coefficients_for_guardians as compute_lagrange_coeffs
)



def create_election_manifest(
    party_names: List[str], 
    candidate_names: List[str]
) -> Manifest:
    """Create a complete election manifest programmatically."""
    # Create geopolitical unit
    geopolitical_unit = GeopoliticalUnit(
        object_id="county-1",
        name="County 1",
        type=ReportingUnitType.county,
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
            vote_variation=VoteVariationType.one_of_m,
            name="County Executive",
            ballot_selections=ballot_selections,
            ballot_title=None,
            ballot_subtitle=None,
            votes_allowed=1,
            number_elected=1,
        ),
    ]
    
    start_date = datetime(2025,1,1)
    end_date = datetime(2025,1,1)
    
    manifest = Manifest(
        election_scope_id=f"election-1",
        spec_version="1.0",
        type=ElectionType.general,
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


def create_plaintext_ballot(party_names, candidate_names, candidate_name: str, ballot_id: str) -> PlaintextBallot:
    """Create a single plaintext ballot for a specific candidate."""
    manifest = create_election_manifest(
        party_names,
        candidate_names,
    )
    
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


def create_encrypted_ballot_service(
    party_names: List[str],
    candidate_names: List[str],
    candidate_name: str,
    ballot_id: str,
    joint_public_key: str,
    commitment_hash: str,
    number_of_guardians: int,
    quorum: int,
    create_plaintext_ballot_func,
    create_election_manifest_func,
    generate_ballot_hash_func
) -> Dict[str, Any]:
    """
    Service function to create and encrypt a ballot.
    
    Args:
        party_names: List of party names
        candidate_names: List of candidate names
        candidate_name: Name of the candidate to vote for
        ballot_id: Unique identifier for the ballot
        joint_public_key: Joint public key as string
        commitment_hash: Commitment hash as string
        number_of_guardians: Number of guardians
        quorum: Quorum for the election
        create_plaintext_ballot_func: Function to create plaintext ballot
        create_election_manifest_func: Function to create election manifest
        generate_ballot_hash_func: Function to generate ballot hash
        
    Returns:
        Dictionary containing the encrypted ballot and hash
        
    Raises:
        ValueError: If ballot encryption fails
    """
    # Convert string inputs to integers for internal processing
    joint_public_key_int = int(joint_public_key)
    commitment_hash_int = int(commitment_hash)
    
    # Create plaintext ballot
    ballot = create_plaintext_ballot_func(party_names, candidate_names, candidate_name, ballot_id)
    
    # Encrypt the ballot
    encrypted_ballot = encrypt_ballot(
        party_names, 
        candidate_names, 
        joint_public_key_int,
        commitment_hash_int,
        ballot,
        number_of_guardians,
        quorum,
        create_election_manifest_func
    )
    
    if not encrypted_ballot:
        raise ValueError('Failed to encrypt ballot')
    
    # Generate ballot hash
    ballot_hash = generate_ballot_hash_func(encrypted_ballot)
    
    # Serialize the ballot for response
    serialized_ballot = to_raw(encrypted_ballot)
    
    return {
        'encrypted_ballot': serialized_ballot,
        'ballot_hash': ballot_hash
    }


def encrypt_ballot(
    party_names: List[str],
    candidate_names: List[str],
    joint_public_key_json: int,
    commitment_hash_json: int,
    plaintext_ballot: PlaintextBallot,
    number_of_guardians: int,
    quorum: int,
    create_election_manifest_func
) -> Optional[CiphertextBallot]:
    """
    Encrypt a single ballot.
    
    Args:
        party_names: List of party names
        candidate_names: List of candidate names
        joint_public_key_json: Joint public key as integer
        commitment_hash_json: Commitment hash as integer
        plaintext_ballot: The plaintext ballot to encrypt
        number_of_guardians: Number of guardians
        quorum: Quorum for the election
        create_election_manifest_func: Function to create election manifest
        
    Returns:
        Encrypted ballot or None if encryption fails
    """
    joint_public_key = int_to_p(joint_public_key_json)
    commitment_hash = int_to_q(commitment_hash_json)
    manifest = create_election_manifest_func(party_names, candidate_names)
    
    # Create election builder and set public key and commitment hash
    election_builder = ElectionBuilder(
        number_of_guardians=number_of_guardians,
        quorum=quorum,
        manifest=manifest
    )
    election_builder.set_public_key(joint_public_key)
    election_builder.set_commitment_hash(commitment_hash)
    
    # Build the election context
    internal_manifest, context = get_optional(election_builder.build())
    
    # Create encryption device and mediator
    device = EncryptionDevice(device_id=1, session_id=1, launch_code=1, location="polling-place")
    encrypter = EncryptionMediator(internal_manifest, context, device)
    
    # Encrypt the ballot
    encrypted_ballot = encrypter.encrypt(plaintext_ballot)
    if encrypted_ballot:
        return get_optional(encrypted_ballot)
    return None
