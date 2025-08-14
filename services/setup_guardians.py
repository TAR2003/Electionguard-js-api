"""
Service for setting up guardians and creating joint key.
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


def setup_guardians_service(
    number_of_guardians: int,
    quorum: int,
    party_names: List[str],
    candidate_names: List[str]
) -> Dict[str, Any]:
    """
    Service function to setup guardians and create joint key.
    
    Args:
        number_of_guardians: Number of guardians to create
        quorum: Minimum number of guardians needed for decryption
        party_names: List of party names
        candidate_names: List of candidate names
        
    Returns:
        Dictionary containing the setup results
        
    Raises:
        ValueError: If quorum validation fails
    """
    # Validate quorum
    if quorum > number_of_guardians:
        raise ValueError('Quorum cannot be greater than number of guardians')
    
    if quorum < 1:
        raise ValueError('Quorum must be at least 1')
    
    # Setup Guardians
    guardians: List[Guardian] = []
    for i in range(number_of_guardians):
        guardian = Guardian.from_nonce(
            str(i + 1),  # guardian id
            i + 1,  # sequence order
            number_of_guardians,
            quorum,
        )
        guardians.append(guardian)
    
    # Setup Key Ceremony Mediator
    mediator = KeyCeremonyMediator(
        "key-ceremony-mediator", 
        guardians[0].ceremony_details
    )
    
    # ROUND 1: Public Key Sharing
    for guardian in guardians:
        mediator.announce(guardian.share_key())
        
    # Share Keys
    for guardian in guardians:
        announced_keys = get_optional(mediator.share_announced())
        for key in announced_keys:
            if guardian.id != key.owner_id:
                guardian.save_guardian_key(key)
    
    # ROUND 2: Election Partial Key Backup Sharing
    for sending_guardian in guardians:
        sending_guardian.generate_election_partial_key_backups()
        
        backups = []
        for designated_guardian in guardians:
            if designated_guardian.id != sending_guardian.id:
                backup = get_optional(
                    sending_guardian.share_election_partial_key_backup(
                        designated_guardian.id
                    )
                )
                backups.append(backup)
        
        mediator.receive_backups(backups)
    
    # Receive Backups
    for designated_guardian in guardians:
        backups = get_optional(mediator.share_backups(designated_guardian.id))
        for backup in backups:
            designated_guardian.save_election_partial_key_backup(backup)
    
    # ROUND 3: Verification of Backups
    for designated_guardian in guardians:
        verifications = []
        for backup_owner in guardians:
            if designated_guardian.id != backup_owner.id:
                verification = designated_guardian.verify_election_partial_key_backup(
                    backup_owner.id
                )
                verifications.append(get_optional(verification))
        
        mediator.receive_backup_verifications(verifications)
    
    # FINAL: Publish Joint Key
    joint_key = get_optional(mediator.publish_joint_key())
    
    # Prepare guardian data including backups for quorum decryption
    guardian_data = []
    private_keys = []
    public_keys = []
    polynomials = []
    
    for guardian in guardians:
        guardian_info = {
            'id': guardian.id,
            'sequence_order': guardian.sequence_order,
            'election_public_key': to_raw(guardian.share_key()),
            'backups': {}
        }
        
        # Store backups for compensated decryption
        for other_guardian in guardians:
            if other_guardian.id != guardian.id:
                backup = guardian._guardian_election_partial_key_backups.get(other_guardian.id)
                if backup:
                    guardian_info['backups'][other_guardian.id] = to_raw(backup)
        
        guardian_data.append(guardian_info)
        
        # Store separate keys and polynomials
        private_keys.append({
            'guardian_id': guardian.id,
            'private_key': str(int(guardian._election_keys.key_pair.secret_key))
        })
        public_keys.append({
            'guardian_id': guardian.id,
            'public_key': str(int(guardian._election_keys.key_pair.public_key))
        })
        polynomials.append({
            'guardian_id': guardian.id,
            'polynomial': to_raw(guardian._election_keys.polynomial)
        })
    
    return {
        'guardians': guardians,
        'joint_public_key': str(int(joint_key.joint_public_key)),
        'commitment_hash': str(int(joint_key.commitment_hash)),
        'guardian_data': guardian_data,
        'private_keys': private_keys,
        'public_keys': public_keys,
        'polynomials': polynomials,
        'number_of_guardians': number_of_guardians,
        'quorum': quorum
    }
