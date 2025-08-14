"""
Service for combining decryption shares.
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



def combine_decryption_shares_service(
    party_names: List[str],
    candidate_names: List[str],
    joint_public_key: str,
    commitment_hash: str,
    ciphertext_tally_json: Dict,
    submitted_ballots_json: List[Dict],
    guardian_data: List[Dict],
    available_guardian_shares: Dict[str, Dict],
    compensated_shares: Dict[str, Dict],
    quorum: int,
    create_election_manifest_func,
    raw_to_ciphertext_tally_func,
    generate_ballot_hash_func,
    generate_ballot_hash_electionguard_func
) -> Dict[str, Any]:
    """
    Service function to combine decryption shares to produce final election results with quorum support.
    
    Args:
        party_names: List of party names
        candidate_names: List of candidate names
        joint_public_key: Joint public key as string
        commitment_hash: Commitment hash as string
        ciphertext_tally_json: Serialized ciphertext tally
        submitted_ballots_json: List of serialized submitted ballots
        guardian_data: List of guardian data
        available_guardian_shares: Regular decryption shares from available guardians
        compensated_shares: Compensated decryption shares for missing guardians
        quorum: Required quorum
        create_election_manifest_func: Function to create election manifest
        raw_to_ciphertext_tally_func: Function to deserialize ciphertext tally
        generate_ballot_hash_func: Function to generate ballot hash
        generate_ballot_hash_electionguard_func: Function to generate ElectionGuard ballot hash
        
    Returns:
        Dictionary containing election results
        
    Raises:
        ValueError: If decryption fails or insufficient guardians
    """
    # Convert string inputs to integers for internal processing
    joint_public_key_int = int(joint_public_key)
    commitment_hash_int = int(commitment_hash)
    
    # Build election context
    manifest = create_election_manifest_func(party_names, candidate_names)
    number_of_guardians = len(guardian_data)
    
    election_builder = ElectionBuilder(
        number_of_guardians=number_of_guardians,
        quorum=quorum,
        manifest=manifest
    )
    joint_public_key_element = int_to_p(joint_public_key_int)
    commitment_hash_element = int_to_q(commitment_hash_int)
    election_builder.set_public_key(joint_public_key_element)
    election_builder.set_commitment_hash(commitment_hash_element)
    internal_manifest, context = get_optional(election_builder.build())
    
    # Process ciphertext tally and ballots
    ciphertext_tally = raw_to_ciphertext_tally_func(ciphertext_tally_json, manifest=manifest)
    submitted_ballots = []
    for ballot_json in submitted_ballots_json:
        if isinstance(ballot_json, dict):
            submitted_ballots.append(from_raw(SubmittedBallot, json.dumps(ballot_json)))
        else:
            submitted_ballots.append(from_raw(SubmittedBallot, ballot_json))
    
    # Configure decryption mediator
    decryption_mediator = DecryptionMediator("decryption-mediator", context)
    
    # First, get all guardian keys from guardian data
    all_guardian_keys = []
    for guardian_info in guardian_data:
        election_public_key_data = guardian_info['election_public_key']
        if isinstance(election_public_key_data, dict):
            election_public_key = from_raw(ElectionPublicKey, json.dumps(election_public_key_data))
        else:
            election_public_key = from_raw(ElectionPublicKey, election_public_key_data)
        all_guardian_keys.append(election_public_key)
    
    # Add available guardian shares (normal decryption shares)
    for guardian_id, share_data in available_guardian_shares.items():
        guardian_public_key_data = share_data['guardian_public_key']
        if isinstance(guardian_public_key_data, dict):
            guardian_public_key = from_raw(ElectionPublicKey, json.dumps(guardian_public_key_data))
        else:
            guardian_public_key = from_raw(ElectionPublicKey, guardian_public_key_data)
            
        tally_share_data = share_data['tally_share']
        if tally_share_data:
            if isinstance(tally_share_data, dict):
                tally_share = from_raw(DecryptionShare, json.dumps(tally_share_data))
            else:
                tally_share = from_raw(DecryptionShare, tally_share_data)
        else:
            tally_share = None
        
        ballot_shares = {}
        for ballot_id, serialized_ballot_share in share_data['ballot_shares'].items():
            if serialized_ballot_share:
                if isinstance(serialized_ballot_share, dict):
                    ballot_shares[ballot_id] = from_raw(DecryptionShare, json.dumps(serialized_ballot_share))
                else:
                    ballot_shares[ballot_id] = from_raw(DecryptionShare, serialized_ballot_share)
        
        decryption_mediator.announce(guardian_public_key, tally_share, ballot_shares)
    
    # Announce missing guardians
    print(f"Processing compensated shares for {len(compensated_shares)} guardians")
    for missing_guardian_id in compensated_shares.keys():
        missing_guardian_info = next((gd for gd in guardian_data if gd['id'] == missing_guardian_id), None)
        if missing_guardian_info:
            missing_guardian_public_key_data = missing_guardian_info['election_public_key']
            if isinstance(missing_guardian_public_key_data, dict):
                missing_guardian_public_key = from_raw(ElectionPublicKey, json.dumps(missing_guardian_public_key_data))
            else:
                missing_guardian_public_key = from_raw(ElectionPublicKey, missing_guardian_public_key_data)
            decryption_mediator.announce_missing(missing_guardian_public_key)
            print(f"Announced missing guardian: {missing_guardian_id}")
    
    # Add compensated shares for missing guardians
    print(f"Processing compensated shares data...")
    for missing_guardian_id, compensated_data in compensated_shares.items():
        print(f"Processing compensated shares for missing guardian: {missing_guardian_id}")
        for available_guardian_id, comp_share_data in compensated_data.items():
            print(f"  - From guardian {available_guardian_id}")
            if comp_share_data.get('compensated_tally_share'):
                compensated_tally_share_data = comp_share_data['compensated_tally_share']
                if isinstance(compensated_tally_share_data, dict):
                    compensated_tally_share = from_raw(CompensatedDecryptionShare, json.dumps(compensated_tally_share_data))
                else:
                    compensated_tally_share = from_raw(CompensatedDecryptionShare, compensated_tally_share_data)
                decryption_mediator.receive_tally_compensation_share(compensated_tally_share)
                print(f"    ✅ Added compensated tally share")
            
            if comp_share_data.get('compensated_ballot_shares'):
                compensated_ballot_shares = {}
                for ballot_id, serialized_comp_ballot_share in comp_share_data['compensated_ballot_shares'].items():
                    if serialized_comp_ballot_share:
                        if isinstance(serialized_comp_ballot_share, dict):
                            compensated_ballot_shares[ballot_id] = from_raw(CompensatedDecryptionShare, json.dumps(serialized_comp_ballot_share))
                        else:
                            compensated_ballot_shares[ballot_id] = from_raw(CompensatedDecryptionShare, serialized_comp_ballot_share)
                
                decryption_mediator.receive_ballot_compensation_shares(compensated_ballot_shares)
                print(f"    ✅ Added {len(compensated_ballot_shares)} compensated ballot shares")
    
    # Reconstruct shares for missing guardians
    print(f"Reconstructing shares for tally and ballots...")
    decryption_mediator.reconstruct_shares_for_tally(ciphertext_tally)
    decryption_mediator.reconstruct_shares_for_ballots(submitted_ballots)
    print(f"✅ Shares reconstructed")
    
    # Ensure announcement is complete
    if not decryption_mediator.announcement_complete():
        # Try to get more details about what's missing
        try:
            # Check if we have enough guardians
            available_count = len(available_guardian_shares)
            missing_count = len(compensated_shares)
            total_announced = available_count + missing_count
            print(f"Debug: Available guardians: {available_count}, Missing (compensated): {missing_count}, Total announced: {total_announced}, Required quorum: {quorum}")
            raise ValueError(f"Announcement not complete - insufficient guardians or shares. Available: {available_count}, Missing: {missing_count}, Quorum: {quorum}")
        except Exception as debug_error:
            raise ValueError(f"Announcement not complete - {str(debug_error)}")
    
    # Get plaintext results
    plaintext_tally = decryption_mediator.get_plaintext_tally(ciphertext_tally, manifest)
    if plaintext_tally is None:
        raise ValueError("Failed to decrypt tally - plaintext_tally is None")
    
    plaintext_spoiled_ballots = decryption_mediator.get_plaintext_ballots(submitted_ballots, manifest)
    if plaintext_spoiled_ballots is None:
        plaintext_spoiled_ballots = {}
    
    # Create sets of cast and spoiled ballot IDs for quick lookup
    cast_ballot_ids = ciphertext_tally.cast_ballot_ids
    spoiled_ballot_ids = ciphertext_tally.spoiled_ballot_ids
    
    # Format the complete results
    results = {
        'election': {
            'name': manifest.name,
            'scope_id': manifest.election_scope_id,
            'type': str(manifest.type),
            'start_date': manifest.start_date.isoformat(),
            'end_date': manifest.end_date.isoformat(),
            'number_of_guardians': number_of_guardians,
            'quorum': quorum,
            'geopolitical_units': [{
                'id': unit.object_id,
                'name': unit.name,
                'type': str(unit.type)
            } for unit in manifest.geopolitical_units],
            'parties': [{
                'id': party.object_id,
                'name': party.name
            } for party in manifest.parties],
            'candidates': [{
                'id': candidate.object_id,
                'name': candidate.name,
                'party_id': candidate.party_id
            } for candidate in manifest.candidates],
            'contests': [{
                'id': contest.object_id,
                'name': contest.name,
                'selections': [{
                    'id': selection.object_id,
                    'candidate_id': selection.candidate_id
                } for selection in contest.ballot_selections]
            } for contest in manifest.contests]
        },
        'results': {
            'total_ballots_cast': len(submitted_ballots),
            'total_valid_ballots': len(cast_ballot_ids),
            'total_spoiled_ballots': len(spoiled_ballot_ids),
            'candidates': {},
            'spoiled_ballots': []
        },
        'verification': {
            'ballots': [],
            'guardians': []
        }
    }
    
    # Process election results
    for contest in plaintext_tally.contests.values():
        for selection in contest.selections.values():
            candidate = selection.object_id
            results['results']['candidates'][candidate] = {
                'votes': str(selection.tally),
                'percentage': str(round(selection.tally / len(cast_ballot_ids) * 100, 2)) if len(cast_ballot_ids) > 0 else "0"
            }
    
    # Process spoiled ballots
    for ballot_id, ballot in plaintext_spoiled_ballots.items():
        if isinstance(ballot, PlaintextBallot):
            # Find the original ballot to compute its initial hash
            original_ballot = next((b for b in submitted_ballots if b.object_id == ballot_id), None)
            initial_hash = generate_ballot_hash_electionguard_func(original_ballot) if original_ballot else "N/A"
            
            ballot_info = {
                'ballot_id': ballot_id,
                'initial_hash': initial_hash,
                'decrypted_hash': generate_ballot_hash_func(ballot),
                'status': 'spoiled',
                'selections': []
            }
            
            for contest in ballot.contests:
                for selection in contest.ballot_selections:
                    if selection.vote == 1:
                        ballot_info['selections'].append({
                            'contest_id': contest.object_id,
                            'selection_id': selection.object_id,
                            'vote': str(selection.vote)
                        })
            
            results['results']['spoiled_ballots'].append(ballot_info)
    
    # Add ballot verification information
    for ballot in submitted_ballots:
        initial_hash = generate_ballot_hash_electionguard_func(ballot)
        
        ballot_info = {
            'ballot_id': ballot.object_id,
            'initial_hash': initial_hash,
            'status': 'spoiled' if ballot.object_id in spoiled_ballot_ids else 'cast'
        }
        
        if ballot.object_id in spoiled_ballot_ids:
            spoiled_ballot = plaintext_spoiled_ballots.get(ballot.object_id)
            if spoiled_ballot:
                ballot_info['decrypted_hash'] = generate_ballot_hash_func(spoiled_ballot)
                ballot_info['verification'] = 'success'
            else:
                ballot_info['decrypted_hash'] = 'N/A'
                ballot_info['verification'] = 'failed'
        else:
            ballot_info['decrypted_hash'] = initial_hash
            ballot_info['verification'] = 'success'
        
        results['verification']['ballots'].append(ballot_info)
    
    # Add guardian information
    for guardian_id, share_data in available_guardian_shares.items():
        guardian_public_key_data = share_data['guardian_public_key']
        if isinstance(guardian_public_key_data, dict):
            guardian_public_key = from_raw(ElectionPublicKey, json.dumps(guardian_public_key_data))
        else:
            guardian_public_key = from_raw(ElectionPublicKey, guardian_public_key_data)
        results['verification']['guardians'].append({
            'id': guardian_public_key.owner_id,
            'sequence_order': str(guardian_public_key.sequence_order),
            'public_key': str(guardian_public_key.key),
            'status': 'available'
        })
    
    # Add missing guardian information
    for missing_guardian_id in compensated_shares.keys():
        guardian_info = next((gd for gd in guardian_data if gd['id'] == missing_guardian_id), None)
        if guardian_info:
            # Get the public key from election_public_key
            missing_guardian_public_key_data = guardian_info['election_public_key']
            if isinstance(missing_guardian_public_key_data, dict):
                missing_guardian_public_key = from_raw(ElectionPublicKey, json.dumps(missing_guardian_public_key_data))
            else:
                missing_guardian_public_key = from_raw(ElectionPublicKey, missing_guardian_public_key_data)
            results['verification']['guardians'].append({
                'id': missing_guardian_id,
                'sequence_order': str(guardian_info['sequence_order']),
                'public_key': str(missing_guardian_public_key.key),
                'status': 'missing (compensated)'
            })
    
    
    
    return results
