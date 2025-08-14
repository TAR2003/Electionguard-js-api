"""
New Guardian Key Ceremony Service for manual key selection.
Each guardian selects their private/public key pair individually.
"""

#!/usr/bin/env python

from flask import Flask, request, jsonify
from typing import Dict, List, Optional, Tuple, Any
import random
from datetime import datetime
import uuid
import json
import hashlib
import base64
from collections import defaultdict

from electionguard.serialize import to_raw, from_raw
from electionguard.constants import get_constants
from electionguard.guardian import Guardian
from electionguard.key_ceremony_mediator import KeyCeremonyMediator
from electionguard.key_ceremony import ElectionKeyPair, ElectionPublicKey, ElectionJointKey
from electionguard.elgamal import ElGamalPublicKey, ElGamalSecretKey, ElGamalCiphertext, elgamal_combine_public_keys
from electionguard.group import ElementModQ, ElementModP, g_pow_p, int_to_p, int_to_q, rand_q
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
from electionguard.utils import get_optional

# Store for ceremony states
ceremony_states = {}

class GuardianKeyCeremonyState:
    """Manages the state of a guardian key ceremony"""
    
    def __init__(self, election_id: str, number_of_guardians: int, quorum: int, party_names: List[str], candidate_names: List[str]):
        self.election_id = election_id
        self.number_of_guardians = number_of_guardians
        self.quorum = quorum
        self.party_names = party_names
        self.candidate_names = candidate_names
        self.guardian_keys = {}  # guardian_id -> {"private_key": str, "public_key": str, "guardian": Guardian}
        self.mediator = None
        self.joint_public_key = None
        self.commitment_hash = None
        self.ceremony_complete = False
        self.created_at = datetime.now()
        
    def add_guardian_keys(self, guardian_id: str, private_key_str: str, public_key_str: str) -> bool:
        """Add guardian's selected keys to the ceremony"""
        try:
            # Convert string keys to appropriate formats
            private_key_int = int(private_key_str)
            public_key_int = int(public_key_str)
            
            # Validate key pair (basic validation)
            private_key = int_to_q(private_key_int)
            public_key = int_to_p(public_key_int)
            
            # Verify the key pair is valid (public_key = g^private_key mod p)
            if g_pow_p(private_key) != public_key:
                print(f"❌ Invalid key pair for guardian {guardian_id}")
                return False
            
            # Create guardian with the provided keys
            sequence_order = len(self.guardian_keys) + 1
            
            # Create a guardian from the provided keys (we'll need to create a custom method)
            guardian = self._create_guardian_with_keys(guardian_id, sequence_order, private_key, public_key)
            
            self.guardian_keys[guardian_id] = {
                "private_key": private_key_str,
                "public_key": public_key_str,
                "guardian": guardian
            }
            
            print(f"✅ Added keys for guardian {guardian_id} (sequence {sequence_order})")
            return True
            
        except Exception as e:
            print(f"❌ Error adding keys for guardian {guardian_id}: {str(e)}")
            return False
    
    def _create_guardian_with_keys(self, guardian_id: str, sequence_order: int, private_key: ElementModQ, public_key: ElementModP) -> Guardian:
        """Create a Guardian object with provided keys"""
        from electionguard.elgamal import ElGamalKeyPair
        from electionguard.key_ceremony import ElectionKeyPair
        from electionguard.election_polynomial import ElectionPolynomial
        from electionguard.ceremony_details import CeremonyDetails
        
        # Create ceremony details
        ceremony_details = CeremonyDetails(self.number_of_guardians, self.quorum)
        
        # Create ElGamal key pair
        key_pair = ElGamalKeyPair(private_key, public_key)
        
        # Create polynomial with the private key as constant term
        polynomial = ElectionPolynomial.generate_polynomial(private_key, self.quorum)
        
        # Create election key pair
        election_key_pair = ElectionKeyPair(
            owner_id=guardian_id,
            sequence_order=sequence_order,
            key_pair=key_pair,
            polynomial=polynomial
        )
        
        # Create guardian
        guardian = Guardian(election_key_pair, ceremony_details)
        return guardian
    
    def is_ready_for_ceremony(self) -> bool:
        """Check if all guardians have submitted their keys"""
        return len(self.guardian_keys) == self.number_of_guardians
    
    def perform_key_ceremony(self) -> bool:
        """Perform the key ceremony to generate joint public key"""
        if not self.is_ready_for_ceremony():
            return False
        
        try:
            # Create mediator
            ceremony_details = list(self.guardian_keys.values())[0]["guardian"].ceremony_details
            self.mediator = KeyCeremonyMediator("ceremony-mediator", ceremony_details)
            
            guardians = [data["guardian"] for data in self.guardian_keys.values()]
            
            # Perform Round 1: Public Key Sharing
            for guardian in guardians:
                self.mediator.announce(guardian.share_key())
                print(f"   ✅ Guardian {guardian.id} announced public key")
            
            # Share Keys
            for guardian in guardians:
                announced_keys = get_optional(self.mediator.share_announced())
                for key in announced_keys:
                    if guardian.id != key.owner_id:
                        guardian.save_guardian_key(key)
                        print(f"   ✅ Guardian {guardian.id} saved key from Guardian {key.owner_id}")
            
            # Perform Round 2: Election Partial Key Backup Sharing
            for sending_guardian in guardians:
                sending_guardian.generate_election_partial_key_backups()
                print(f"   ✅ Guardian {sending_guardian.id} generated partial key backups")
                
                for designated_guardian in guardians:
                    if designated_guardian.id != sending_guardian.id:
                        backup = get_optional(
                            sending_guardian.share_election_partial_key_backup(designated_guardian.id)
                        )
                        if backup is not None:
                            self.mediator.receive_backup(backup)
                            print(f"   ✅ Backup shared from {sending_guardian.id} to {designated_guardian.id}")
            
            # Share backups with guardians
            for guardian in guardians:
                backups = get_optional(self.mediator.share_backups(guardian.id))
                for backup in backups:
                    guardian.save_election_partial_key_backup(backup)
                    print(f"   ✅ Guardian {guardian.id} saved backup from Guardian {backup.owner_id}")
            
            # Perform Round 3: Verification
            for guardian in guardians:
                for other_guardian in guardians:
                    if guardian.id != other_guardian.id:
                        verification = guardian.verify_election_partial_key_backup(other_guardian.id)
                        if verification is not None:
                            self.mediator.receive_verification(verification)
                            print(f"   ✅ Guardian {guardian.id} verified backup from Guardian {other_guardian.id}")
            
            # Share verifications
            for guardian in guardians:
                verifications = get_optional(self.mediator.share_verifications(guardian.id))
                for verification in verifications:
                    guardian.save_election_partial_key_verification(verification)
                    print(f"   ✅ Guardian {guardian.id} saved verification from Guardian {verification.sender_guardian_id}")
            
            # Publish joint key
            joint_key = self.mediator.publish_joint_key()
            if joint_key is not None:
                self.joint_public_key = int(joint_key.joint_public_key)
                self.commitment_hash = int(joint_key.commitment_hash)
                self.ceremony_complete = True
                print(f"✅ Joint election key published: {self.joint_public_key}")
                print(f"✅ Commitment hash: {self.commitment_hash}")
                return True
            else:
                print("❌ Failed to generate joint key")
                return False
                
        except Exception as e:
            print(f"❌ Error performing key ceremony: {str(e)}")
            return False
    
    def get_ceremony_result(self) -> Dict[str, Any]:
        """Get the ceremony result for the backend"""
        if not self.ceremony_complete:
            return None
        
        guardians_data = []
        private_keys = []
        public_keys = []
        polynomials = []
        
        for guardian_id, data in self.guardian_keys.items():
            guardian = data["guardian"]
            
            # Collect guardian data
            guardian_dict = {
                "id": guardian.id,
                "sequence_order": guardian._election_keys.sequence_order,
                "public_key": int(guardian._election_keys.key_pair.public_key)
            }
            guardians_data.append(to_raw(guardian_dict))
            
            # Collect private keys and polynomials
            private_keys.append(data["private_key"])
            public_keys.append(data["public_key"])
            polynomials.append(to_raw(guardian._election_keys.polynomial))
        
        # Create manifest
        manifest = create_election_manifest(self.party_names, self.candidate_names)
        
        return {
            'status': 'success',
            'joint_public_key': str(self.joint_public_key),
            'commitment_hash': str(self.commitment_hash),
            'manifest': to_raw(manifest),
            'guardian_data': guardians_data,
            'private_keys': private_keys,
            'public_keys': public_keys,
            'polynomials': polynomials,
            'number_of_guardians': self.number_of_guardians,
            'quorum': self.quorum
        }

def create_election_manifest(party_names: List[str], candidate_names: List[str]) -> Manifest:
    """Create election manifest from party and candidate names"""
    try:
        parties = []
        candidates = []
        selections = []
        
        # Create parties
        for i, party_name in enumerate(party_names):
            party_id = f"party-{i + 1}"
            party = Party(
                object_id=party_id,
                name={"en": party_name},
                abbreviation=party_name[:3].upper()
            )
            parties.append(party)
        
        # Create candidates with associated parties
        for i, candidate_name in enumerate(candidate_names):
            candidate_id = f"candidate-{i + 1}"
            party_id = f"party-{(i % len(party_names)) + 1}" if party_names else None
            
            candidate = Candidate(
                object_id=candidate_id,
                ballot_name={"en": candidate_name},
                party_id=party_id
            )
            candidates.append(candidate)
            
            # Create selection for this candidate
            selection = SelectionDescription(
                object_id=f"selection-{i + 1}",
                candidate_id=candidate_id,
                sequence_order=i
            )
            selections.append(selection)
        
        # Create contest
        contest = Contest(
            object_id="president-contest",
            sequence_order=0,
            electoral_district_id="district-1",
            vote_variation=VoteVariationType.one_of_m,
            number_elected=1,
            name="President Election",
            ballot_selections=selections
        )
        
        # Create geopolitical unit
        geo_unit = GeopoliticalUnit(
            object_id="district-1",
            name="Election District",
            type=ReportingUnitType.unknown
        )
        
        # Create ballot style
        ballot_style = BallotStyle(
            object_id="ballot-style-1",
            geopolitical_unit_ids=["district-1"],
            party_ids=[p.object_id for p in parties] if parties else None,
            image_uri=None
        )
        
        # Create contact information
        contact_info = ContactInformation(
            name="Election Administrator"
        )
        
        # Create manifest
        manifest = Manifest(
            election_scope_id="election-1",
            spec_version=SpecVersion.v1_0,
            type=ElectionType.general,
            start_date=datetime.now(),
            end_date=datetime.now(),
            geopolitical_units=[geo_unit],
            parties=parties,
            candidates=candidates,
            contests=[contest],
            ballot_styles=[ballot_style],
            name={"en": "Election"},
            contact_information=contact_info
        )
        
        return manifest
        
    except Exception as e:
        print(f"Error creating manifest: {str(e)}")
        raise e

def init_guardian_ceremony_service(election_id: str, number_of_guardians: int, quorum: int, party_names: List[str], candidate_names: List[str]) -> Dict[str, Any]:
    """Initialize a new guardian key ceremony"""
    try:
        ceremony = GuardianKeyCeremonyState(election_id, number_of_guardians, quorum, party_names, candidate_names)
        ceremony_states[election_id] = ceremony
        
        return {
            'status': 'success',
            'message': 'Guardian ceremony initialized',
            'election_id': election_id,
            'guardians_needed': number_of_guardians,
            'guardians_submitted': 0
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }

def submit_guardian_keys_service(election_id: str, guardian_id: str, private_key: str, public_key: str) -> Dict[str, Any]:
    """Submit guardian's selected keys"""
    try:
        if election_id not in ceremony_states:
            return {
                'status': 'error',
                'message': 'Ceremony not found'
            }
        
        ceremony = ceremony_states[election_id]
        
        if ceremony.ceremony_complete:
            return {
                'status': 'error',
                'message': 'Ceremony already completed'
            }
        
        if guardian_id in ceremony.guardian_keys:
            return {
                'status': 'error',
                'message': 'Guardian keys already submitted'
            }
        
        success = ceremony.add_guardian_keys(guardian_id, private_key, public_key)
        
        if not success:
            return {
                'status': 'error',
                'message': 'Invalid key pair'
            }
        
        guardians_submitted = len(ceremony.guardian_keys)
        all_submitted = ceremony.is_ready_for_ceremony()
        
        return {
            'status': 'success',
            'message': f'Keys submitted for guardian {guardian_id}',
            'guardians_submitted': guardians_submitted,
            'guardians_needed': ceremony.number_of_guardians,
            'all_submitted': all_submitted
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }

def finalize_guardian_ceremony_service(election_id: str) -> Dict[str, Any]:
    """Perform the key ceremony and generate joint public key"""
    try:
        if election_id not in ceremony_states:
            return {
                'status': 'error',
                'message': 'Ceremony not found'
            }
        
        ceremony = ceremony_states[election_id]
        
        if not ceremony.is_ready_for_ceremony():
            return {
                'status': 'error',
                'message': f'Not all guardians have submitted keys. Need {ceremony.number_of_guardians}, have {len(ceremony.guardian_keys)}'
            }
        
        if ceremony.ceremony_complete:
            return ceremony.get_ceremony_result()
        
        success = ceremony.perform_key_ceremony()
        
        if success:
            return ceremony.get_ceremony_result()
        else:
            return {
                'status': 'error',
                'message': 'Failed to complete key ceremony'
            }
            
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }

def get_ceremony_status_service(election_id: str) -> Dict[str, Any]:
    """Get the current status of a ceremony"""
    try:
        if election_id not in ceremony_states:
            return {
                'status': 'error',
                'message': 'Ceremony not found'
            }
        
        ceremony = ceremony_states[election_id]
        
        return {
            'status': 'success',
            'election_id': election_id,
            'guardians_needed': ceremony.number_of_guardians,
            'guardians_submitted': len(ceremony.guardian_keys),
            'submitted_guardians': list(ceremony.guardian_keys.keys()),
            'ceremony_complete': ceremony.ceremony_complete,
            'created_at': ceremony.created_at.isoformat()
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }
