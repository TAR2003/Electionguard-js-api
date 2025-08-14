"""
Service for creating compensated decryption shares.
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
from electionguard.key_ceremony import ElectionKeyPair, ElectionPublicKey, ElectionPartialKeyBackup
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


def compute_compensated_ballot_shares(
    missing_guardian_coordinate: ElementModQ,
    present_guardian_key: ElectionPublicKey,
    missing_guardian_key: ElectionPublicKey,
    ballots: List[SubmittedBallot],
    context: CiphertextElectionContext
) -> Dict[BallotId, Optional[CompensatedDecryptionShare]]:
    """Compute compensated decryption shares for ballots."""
    shares = {}
    for ballot in ballots:
        share = compute_compensated_decryption_share_for_ballot(
            missing_guardian_coordinate,
            missing_guardian_key,
            present_guardian_key,
            ballot,
            context,
        )
        shares[ballot.object_id] = share
    return shares


def create_compensated_decryption_service(
    party_names: List[str],
    candidate_names: List[str],
    available_guardian_id: str,
    missing_guardian_id: str,
    available_guardian_data: Dict,
    missing_guardian_data: Dict,
    available_private_key: Dict,
    available_public_key: Dict,
    available_polynomial: Dict,
    ciphertext_tally_json: Dict,
    submitted_ballots_json: List[Dict],
    joint_public_key: str,
    commitment_hash: str,
    number_of_guardians: int,
    quorum: int,
    create_election_manifest_func,
    raw_to_ciphertext_tally_func,
    compute_compensated_ballot_shares_func
) -> Dict[str, Any]:
    """
    Service function to compute compensated decryption shares for missing guardians.
    
    Args:
        party_names: List of party names
        candidate_names: List of candidate names
        available_guardian_id: ID of the available guardian
        missing_guardian_id: ID of the missing guardian
        available_guardian_data: Guardian data for the available guardian
        missing_guardian_data: Guardian data for the missing guardian
        available_private_key: Private key data for the available guardian
        available_public_key: Public key data for the available guardian
        available_polynomial: Polynomial data for the available guardian
        ciphertext_tally_json: Serialized ciphertext tally
        submitted_ballots_json: List of serialized submitted ballots
        joint_public_key: Joint public key as string
        commitment_hash: Commitment hash as string
        number_of_guardians: Number of guardians
        quorum: Quorum threshold
        create_election_manifest_func: Function to create election manifest
        raw_to_ciphertext_tally_func: Function to deserialize ciphertext tally
        compute_compensated_ballot_shares_func: Function to compute compensated ballot shares
        
    Returns:
        Dictionary containing compensated shares
        
    Raises:
        ValueError: If guardian data is invalid or backup cannot be decrypted
    """
    # Convert string inputs to integers for internal processing
    joint_public_key_int = int(joint_public_key)
    commitment_hash_int = int(commitment_hash)
    
    # Get the backup for the missing guardian from the available guardian
    backup_data = available_guardian_data.get('backups', {}).get(missing_guardian_id)
    if not backup_data:
        raise ValueError(f"No backup found for missing guardian {missing_guardian_id} in available guardian {available_guardian_id}")
    
    # Create election public keys
    # Handle election_public_key data - check if it's already a dict or needs JSON parsing
    available_election_public_key_data = available_guardian_data['election_public_key']
    if isinstance(available_election_public_key_data, dict):
        available_guardian_public_key = from_raw(ElectionPublicKey, json.dumps(available_election_public_key_data))
    else:
        available_guardian_public_key = from_raw(ElectionPublicKey, available_election_public_key_data)
        
    missing_election_public_key_data = missing_guardian_data['election_public_key']
    if isinstance(missing_election_public_key_data, dict):
        missing_guardian_public_key = from_raw(ElectionPublicKey, json.dumps(missing_election_public_key_data))
    else:
        missing_guardian_public_key = from_raw(ElectionPublicKey, missing_election_public_key_data)
    
    # Decrypt the backup to get the coordinate
    # Handle backup data - check if it's already a dict or needs JSON parsing
    if isinstance(backup_data, dict):
        backup = from_raw(ElectionPartialKeyBackup, json.dumps(backup_data))
    else:
        backup = from_raw(ElectionPartialKeyBackup, backup_data)
    
    # Find the private key and polynomial for the available guardian
    available_private_key_info = available_private_key
    available_polynomial_info = available_polynomial
    
    if not available_private_key_info or not available_polynomial_info:
        raise ValueError(f"Missing key or polynomial data for available guardian {available_guardian_id}")
    
    # Create available guardian's election key pair to decrypt backup
    available_private_key_element = int_to_q(int(available_private_key_info['private_key']))
    
    # Find the public key for the available guardian
    available_public_key_info = available_public_key
    
    if not available_public_key_info:
        raise ValueError(f"Missing public key data for available guardian {available_guardian_id}")
    
    available_public_key_element = int_to_p(int(available_public_key_info['public_key']))
    
    # Handle polynomial data - check if it's already a dict or needs JSON parsing
    polynomial_data = available_polynomial_info['polynomial']
    if isinstance(polynomial_data, dict):
        # Already deserialized, convert back to JSON string for from_raw
        available_polynomial = from_raw(ElectionPolynomial, json.dumps(polynomial_data))
    else:
        # It's a JSON string, use directly
        available_polynomial = from_raw(ElectionPolynomial, polynomial_data)
    
    available_election_key = ElectionKeyPair(
        owner_id=available_guardian_id,
        sequence_order=available_guardian_data['sequence_order'],
        key_pair=ElGamalKeyPair(available_private_key_element, available_public_key_element),
        polynomial=available_polynomial
    )
    
    # Decrypt the backup to get the missing guardian's coordinate
    missing_guardian_coordinate = decrypt_backup(backup, available_election_key)
    if not missing_guardian_coordinate:
        raise ValueError(f"Failed to decrypt backup for missing guardian {missing_guardian_id}")
    
    manifest = create_election_manifest_func(party_names, candidate_names)
    
    election_builder = ElectionBuilder(
        number_of_guardians=number_of_guardians,
        quorum=quorum,
        manifest=manifest
    )
    
    # Set election parameters
    joint_public_key_element = int_to_p(joint_public_key_int)
    commitment_hash_element = int_to_q(commitment_hash_int)
    election_builder.set_public_key(joint_public_key_element)
    election_builder.set_commitment_hash(commitment_hash_element)
        
    # Build the election context
    internal_manifest, context = get_optional(election_builder.build())
    ciphertext_tally = raw_to_ciphertext_tally_func(ciphertext_tally_json, manifest=manifest)
    submitted_ballots = []
    for ballot_json in submitted_ballots_json:
        if isinstance(ballot_json, dict):
            submitted_ballots.append(from_raw(SubmittedBallot, json.dumps(ballot_json)))
        else:
            submitted_ballots.append(from_raw(SubmittedBallot, ballot_json))

    # Compute compensated shares
    compensated_tally_share = compute_compensated_decryption_share(
        missing_guardian_coordinate,
        available_guardian_public_key,
        missing_guardian_public_key,
        ciphertext_tally,
        context
    )
    
    compensated_ballot_shares = compute_compensated_ballot_shares_func(
        missing_guardian_coordinate,
        available_guardian_public_key,
        missing_guardian_public_key,
        submitted_ballots,
        context
    )
    
    # Serialize each component
    serialized_tally_share = to_raw(compensated_tally_share) if compensated_tally_share else None
    serialized_ballot_shares = {}
    for ballot_id, ballot_share in compensated_ballot_shares.items():
        serialized_ballot_shares[ballot_id] = to_raw(ballot_share) if ballot_share else None
    
    return {
        'compensated_tally_share': serialized_tally_share,
        'compensated_ballot_shares': serialized_ballot_shares
    }
