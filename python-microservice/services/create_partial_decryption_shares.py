"""Service for creating partial decryption shares."""

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


def compute_ballot_shares(
    _election_keys: ElectionKeyPair,
    ballots: List[SubmittedBallot],
    context: CiphertextElectionContext
) -> Dict[BallotId, Optional[DecryptionShare]]:
    """Compute the decryption shares of ballots."""
    shares = {}
    for ballot in ballots:
        share = compute_decryption_share_for_ballot(
            _election_keys,
            ballot,
            context,
        )
        shares[ballot.object_id] = share
    return shares


def compute_guardian_decryption_shares(
    party_names,
    candidate_names,
    guardian_id: str,
    guardian_data: Dict,
    ciphertext_tally_json,
    submitted_ballots_json,
    joint_public_key_json,
    commitment_hash_json,
    election_data: Dict,
    raw_to_ciphertext_tally_func,
    create_election_manifest_func
) -> Dict[str, Any]:
    """Compute decryption shares for a single guardian."""
    # Find the guardian data for this guardian
    guardian_info = None
    for gd in guardian_data:
        if gd['id'] == guardian_id:
            guardian_info = gd
            break
    
    if not guardian_info:
        raise ValueError(f"Guardian {guardian_id} not found in guardian data")
    
    # Convert inputs to proper types
    public_key = int_to_p(int(guardian_info['public_key']))
    private_key = int_to_q(int(guardian_info['private_key']))
    
    # Handle polynomial data - check if it's already a dict or needs JSON parsing
    polynomial_data = guardian_info['polynomial']
    if isinstance(polynomial_data, dict):
        # Already deserialized, convert back to JSON string for from_raw
        polynomial = from_raw(ElectionPolynomial, json.dumps(polynomial_data))
    else:
        # It's a JSON string, use directly
        polynomial = from_raw(ElectionPolynomial, polynomial_data)
    
    # Create election key pair for this guardian
    election_key = ElectionKeyPair(
        owner_id=guardian_id,
        sequence_order=guardian_info['sequence_order'],
        key_pair=ElGamalKeyPair(private_key, public_key),
        polynomial=polynomial
    )
    
    manifest = create_election_manifest_func(party_names, candidate_names)
    
    # Use stored election data for accurate setup
    number_of_guardians = election_data.get('number_of_guardians', len(guardian_data))
    quorum = election_data.get('quorum', len(guardian_data))
    
    election_builder = ElectionBuilder(
        number_of_guardians=number_of_guardians,
        quorum=quorum,
        manifest=manifest
    )
    
    # Set election parameters
    joint_public_key = int_to_p(joint_public_key_json)
    commitment_hash = int_to_q(commitment_hash_json)
    election_builder.set_public_key(joint_public_key)
    election_builder.set_commitment_hash(commitment_hash)
        
    # Build the election context
    internal_manifest, context = get_optional(election_builder.build())
    ciphertext_tally = raw_to_ciphertext_tally_func(ciphertext_tally_json, manifest=manifest)
    submitted_ballots = []
    for ballot_json in submitted_ballots_json:
        if isinstance(ballot_json, dict):
            submitted_ballots.append(from_raw(SubmittedBallot, json.dumps(ballot_json)))
        else:
            submitted_ballots.append(from_raw(SubmittedBallot, ballot_json))

    # Compute shares
    guardian_public_key = election_key.share()
    tally_share = compute_decryption_share(election_key, ciphertext_tally, context)
    ballot_shares = compute_ballot_shares(election_key, submitted_ballots, context)
    
    # Serialize each component
    serialized_public_key = to_raw(guardian_public_key) if guardian_public_key else None
    serialized_tally_share = to_raw(tally_share) if tally_share else None

    serialized_ballot_shares = {}
    for ballot_id, ballot_share in ballot_shares.items():
        serialized_ballot_shares[ballot_id] = to_raw(ballot_share) if ballot_share else None
    
    return {
        'guardian_public_key': serialized_public_key,
        'tally_share': serialized_tally_share,
        'ballot_shares': serialized_ballot_shares
    }


def create_partial_decryption_service(
    party_names,
    candidate_names,
    guardian_id: str,
    guardian_data: Dict,
    ciphertext_tally_json,
    submitted_ballots_json,
    joint_public_key_json,
    commitment_hash_json,
    election_data: Dict,
    raw_to_ciphertext_tally_func,
    create_election_manifest_func
) -> Dict[str, Any]:
    """Service function for creating partial decryption shares."""
    return compute_guardian_decryption_shares(
        party_names,
        candidate_names,
        guardian_id,
        guardian_data,
        ciphertext_tally_json,
        submitted_ballots_json,
        joint_public_key_json,
        commitment_hash_json,
        election_data,
        raw_to_ciphertext_tally_func,
        create_election_manifest_func
    )
