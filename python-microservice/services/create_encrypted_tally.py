"""
Service for creating encrypted tally from ballots.
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



def ciphertext_tally_to_raw(tally: CiphertextTally) -> Dict:
    """Convert a CiphertextTally to a raw dictionary for serialization."""
    return {
        "_encryption": to_raw(tally._encryption),
        "cast_ballot_ids": list(tally.cast_ballot_ids),
        "spoiled_ballot_ids": list(tally.spoiled_ballot_ids),
        "contests": {contest_id: to_raw(contest) for contest_id, contest in tally.contests.items()},
        "_internal_manifest": to_raw(tally._internal_manifest),
        "_manifest": to_raw(tally._internal_manifest.manifest)
    }


def raw_to_ciphertext_tally(raw: Dict, manifest: Manifest = None) -> CiphertextTally:
    """Reconstruct a CiphertextTally from its raw dictionary representation."""
    internal_manifest = InternalManifest(manifest)
    
    tally = CiphertextTally(
        object_id=raw.get("object_id", ""),
        _internal_manifest=internal_manifest,
        _encryption=from_raw(CiphertextElectionContext, raw["_encryption"]),
    )
    
    tally.cast_ballot_ids = set(raw["cast_ballot_ids"])
    tally.spoiled_ballot_ids = set(raw["spoiled_ballot_ids"])
    
    tally.contests = {
        contest_id: from_raw(CiphertextTallyContest, contest_raw)
        for contest_id, contest_raw in raw["contests"].items()
    }
    
    return tally


def create_encrypted_tally_service(
    party_names: List[str],
    candidate_names: List[str],
    joint_public_key: str,
    commitment_hash: str,
    encrypted_ballots: List[Dict],
    number_of_guardians: int,
    quorum: int,
    create_election_manifest_func,
    ciphertext_tally_to_raw_func
) -> Dict[str, Any]:
    """
    Service function to tally encrypted ballots.
    
    Args:
        party_names: List of party names
        candidate_names: List of candidate names
        joint_public_key: Joint public key as string
        commitment_hash: Commitment hash as string
        encrypted_ballots: List of encrypted ballot dictionaries
        number_of_guardians: Number of guardians
        quorum: Quorum for the election
        create_election_manifest_func: Function to create election manifest
        ciphertext_tally_to_raw_func: Function to serialize ciphertext tally
        
    Returns:
        Dictionary containing the tally results
        
    Raises:
        ValueError: If no ballots provided or tally fails
    """
    if not encrypted_ballots:
        raise ValueError('No ballots to tally. Provide encrypted ballots.')
    
    # Convert string inputs to integers for internal processing
    joint_public_key_int = int(joint_public_key)
    commitment_hash_int = int(commitment_hash)
    
    ciphertext_tally_json, submitted_ballots_json = tally_encrypted_ballots(
        party_names,
        candidate_names,
        joint_public_key_int,
        commitment_hash_int,
        encrypted_ballots,
        number_of_guardians,
        quorum,
        create_election_manifest_func,
        ciphertext_tally_to_raw_func
    )
    
    return {
        'ciphertext_tally': ciphertext_tally_json,
        'submitted_ballots': submitted_ballots_json
    }


def tally_encrypted_ballots(
    party_names: List[str],
    candidate_names: List[str],
    joint_public_key_json: int,
    commitment_hash_json: int,
    encrypted_ballots_json: List[Dict],
    number_of_guardians: int,
    quorum: int,
    create_election_manifest_func,
    ciphertext_tally_to_raw_func
) -> Tuple[Dict, List[Dict]]:
    """
    Tally encrypted ballots.
    
    Args:
        party_names: List of party names
        candidate_names: List of candidate names
        joint_public_key_json: Joint public key as integer
        commitment_hash_json: Commitment hash as integer
        encrypted_ballots_json: List of encrypted ballot dictionaries
        number_of_guardians: Number of guardians
        quorum: Quorum for the election
        create_election_manifest_func: Function to create election manifest
        ciphertext_tally_to_raw_func: Function to serialize ciphertext tally
        
    Returns:
        Tuple of (tally_json, submitted_ballots_json)
    """
    joint_public_key = int_to_p(joint_public_key_json)
    commitment_hash = int_to_q(commitment_hash_json)
    encrypted_ballots: List[CiphertextBallot] = []
    for encrypted_ballot_json in encrypted_ballots_json:
        encrypted_ballots.append(from_raw(CiphertextBallot, encrypted_ballot_json))
    
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
    
    # Create ballot store and ballot box
    ballot_store = DataStore()
    ballot_box = BallotBox(internal_manifest, context, ballot_store)
    
    # Submit ballots - cast all ballots
    submitted_ballots = []
    for i, ballot in enumerate(encrypted_ballots):
        # Cast all ballots
        submitted = ballot_box.cast(ballot)
        if submitted:
            submitted_ballots.append(get_optional(submitted))
    
    # Tally the ballots
    ciphertext_tally = get_optional(
        tally_ballots(ballot_store, internal_manifest, context)
    )
    
    ciphertext_tally_json = ciphertext_tally_to_raw_func(ciphertext_tally)
    submitted_ballots_json = [to_raw(submitted_ballot) for submitted_ballot in submitted_ballots]
    return ciphertext_tally_json, submitted_ballots_json
