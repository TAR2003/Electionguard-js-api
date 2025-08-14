#!/usr/bin/env python

from flask import Flask, request, jsonify
from typing import Dict, List, Optional, Tuple, Any
import random
from datetime import datetime
import uuid
from collections import defaultdict
import hashlib
import json
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import os
import base64
import secrets
import string
import logging
from functools import wraps
from datetime import timedelta
from dotenv import load_dotenv
load_dotenv()  # Add this at the top of your file
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
from services.setup_guardians import setup_guardians_service
from services.guardian_key_ceremony import (
    init_guardian_ceremony_service,
    submit_guardian_keys_service,
    finalize_guardian_ceremony_service,
    get_ceremony_status_service
)
from services.create_encrypted_ballot import create_encrypted_ballot_service
from services.create_encrypted_tally import create_encrypted_tally_service
from services.create_partial_decryption import create_partial_decryption_service
from services.create_compensated_decryption_shares import create_compensated_decryption_service, compute_compensated_ballot_shares
from services.combine_decryption_shares import combine_decryption_shares_service
from services.create_partial_decryption_shares import compute_ballot_shares, compute_guardian_decryption_shares
from services.create_encrypted_ballot import create_election_manifest, create_plaintext_ballot
from services.create_encrypted_tally import ciphertext_tally_to_raw, raw_to_ciphertext_tally

# Import post-quantum cryptography (Kyber1024)
try:
    import pqcrypto.kem.ml_kem_1024 as kyber1024
    from pqcrypto.kem.ml_kem_1024 import generate_keypair, encrypt, decrypt
    PQ_AVAILABLE = True
except ImportError:
    print("Warning: pqcrypto not available. Install with: pip install pqcrypto")
    PQ_AVAILABLE = False

app = Flask(__name__)

# Security Configuration
PQ_ALGORITHM = "ML-KEM-1024"  # Official NIST name
SCRYPT_SALT_LENGTH = 32
SCRYPT_LENGTH = 32
SCRYPT_N = 2**16  # Reduced from 2**20 for speed (still secure: ~65ms vs 3s)
SCRYPT_R = 8
SCRYPT_P = 1
AES_KEY_LENGTH = 32
PASSWORD_LENGTH = 32  # Reduced for speed (still 256-bit entropy)
MAX_PAYLOAD_SIZE = 1 * 1024 * 1024  # 1MB limit for memory efficiency

# Master key - MUST be stored securely in production (HSM, Key Vault, etc.)
MASTER_KEY = os.environ.get('MASTER_KEY_PQ')
if not MASTER_KEY:
    print("WARNING: MASTER_KEY not set in environment. Using random key (data will be lost on restart)")
    MASTER_KEY = os.urandom(32)
elif isinstance(MASTER_KEY, str):
    print('master key found : ' , MASTER_KEY)
    MASTER_KEY = base64.b64decode(MASTER_KEY)

# Rate limiting storage (in production, use Redis/database)
rate_limit_storage = {}

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def print_json(data, str_):
    with open("APIformat.txt", "a") as f:
        print(f"\n---------------\nData: {str_}", file=f)
        for key, value in data.items():
            if isinstance(value, list):
                if not value:
                    value_type = "list (empty)"
                else:
                    value_type = f"list of ({type(value[0]).__name__})"
            else:
                value_type = type(value).__name__
            print(f"{key}: {value_type}", file=f)
        print(f"End of {str_}\n------------------\n\n", file=f)

def print_data(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


# Helper functions for serialization/deserialization
def serialize_dict_to_string(data):
    """Convert dict to JSON string with safe int handling"""
    if isinstance(data, dict):
        return json.dumps(data, ensure_ascii=False)
    return data

def deserialize_string_to_dict(data):
    """Convert JSON string to dict with safe int handling"""
    if isinstance(data, dict):
        # Already a dict (from request.json), return as-is
        return data
    elif isinstance(data, str):
        try:
            return json.loads(data)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON string: {e}")
    else:
        raise ValueError(f"Expected string or dict, got {type(data)}")

def serialize_list_of_dicts_to_list_of_strings(data):
    """Convert List[dict] to List[str] with safe int handling"""
    if isinstance(data, list):
        if not data:
            return []
        if isinstance(data[0], dict):
            return [json.dumps(item, ensure_ascii=False) for item in data]
    return data

def deserialize_list_of_strings_to_list_of_dicts(data):
    """Convert List[str] to List[dict] with safe int handling"""
    if isinstance(data, list):
        if not data:
            return []
        if isinstance(data[0], dict):
            # Already a list of dicts (from request.json), return as-is
            return data
        elif isinstance(data[0], str):
            try:
                return [json.loads(item) for item in data]
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in list: {e}")
        else:
            raise ValueError(f"Expected list of strings or dicts, got list of {type(data[0])}")
    elif isinstance(data, str):
        # Single string that should be parsed as JSON
        try:
            parsed = json.loads(data)
            if isinstance(parsed, list):
                return parsed
            else:
                return [parsed]
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON string: {e}")
    else:
        raise ValueError(f"Expected list or string, got {type(data)}")

def safe_int_conversion(value):
    """Safely convert values to int, handling JSON string->int issues"""
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            raise ValueError(f"Cannot convert string '{value}' to integer")
    elif isinstance(value, float):
        return int(value)
    elif value is None:
        raise ValueError("Cannot convert None to integer")
    return value

# Global storage for election data
election_data = {
    'guardians': None,
    'joint_public_key': None,
    'commitment_hash': None,
    'manifest': None,
    'encrypted_ballots': [],
    'ciphertext_tally': None,
    'submitted_ballots': None,
    'guardian_shares': [],
    'number_of_guardians': 0,
    'quorum': 0
}

geopolitical_unit = GeopoliticalUnit(
    object_id="county-1",
    name="County 1",
    type=ReportingUnitType.county,
    contact_information=None,
)

ballot_style = BallotStyle(
    object_id="ballot-style-1",
    geopolitical_unit_ids=["county-1"],
    party_ids=None,
    image_uri=None,
)


def generate_ballot_hash(ballot: Any) -> str:
    """Generate a cryptographic hash for the ballot using ElectionGuard's built-in hash function."""
    if hasattr(ballot, 'crypto_hash'):
        # Use ElectionGuard's built-in crypto_hash method if available
        return ballot.crypto_hash.to_hex()
    else:
        # Fallback to serialization-based hashing for other objects
        ballot_bytes = to_raw(ballot).encode('utf-8')
        return hashlib.sha256(ballot_bytes).hexdigest()

def generate_ballot_hash_electionguard(ballot: Any) -> str:
    """Generate a cryptographic hash using ElectionGuard's hash_elems function."""
    if hasattr(ballot, 'object_id') and hasattr(ballot, 'crypto_hash'):
        # Use the ballot's built-in crypto_hash which is computed using ElectionGuard's hash_elems
        return ballot.crypto_hash.to_hex()
    else:
        # For other objects, serialize and hash using ElectionGuard's hash_elems
        serialized = to_raw(ballot)
        hash_result = hash_elems(serialized)
        return hash_result.to_hex()

def generate_ballot_hash_from_serialized(serialized_ballot: Dict) -> str:
    """Generate a SHA-256 hash from a serialized ballot dictionary."""
    import json
    # Convert dict to JSON string with consistent ordering
    ballot_json = json.dumps(serialized_ballot, sort_keys=True)
    return hashlib.sha256(ballot_json.encode('utf-8')).hexdigest()

# New helper functions for post-quantum cryptography
def rate_limit(max_requests=10, window_minutes=1):
    """Simple rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = datetime.now()
            
            # Clean old entries
            cutoff_time = current_time - timedelta(minutes=window_minutes)
            if client_ip in rate_limit_storage:
                rate_limit_storage[client_ip] = [
                    req_time for req_time in rate_limit_storage[client_ip] 
                    if req_time > cutoff_time
                ]
            
            # Check rate limit
            if client_ip not in rate_limit_storage:
                rate_limit_storage[client_ip] = []
            
            if len(rate_limit_storage[client_ip]) >= max_requests:
                return jsonify({'error': 'Rate limit exceeded'}), 429
            
            rate_limit_storage[client_ip].append(current_time)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_input(data, required_fields):
    """Validate input data and check for required fields"""
    if not data:
        return "No data provided"
    
    for field in required_fields:
        if field not in data:
            return f"Missing required field: {field}"
    
    # Check payload size
    if len(json.dumps(data)) > MAX_PAYLOAD_SIZE:
        return "Payload too large"
    
    return None

def generate_strong_password():
    """Generate a 32-character cryptographically secure password (optimized for speed)"""
    # Optimized character set for speed while maintaining security
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(PASSWORD_LENGTH))

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Optimized key derivation with caching for repeated operations"""
    kdf = Scrypt(
        salt=salt,
        length=SCRYPT_LENGTH,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def fast_encrypt_with_master_key(plaintext: bytes) -> bytes:
    """Optimized encryption with memory-efficient operations"""
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    cipher = Cipher(algorithms.AES(MASTER_KEY), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Process in one go for speed
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Minimize memory copies
    result = bytearray(12 + 16 + len(ciphertext))
    result[:12] = nonce
    result[12:28] = encryptor.tag
    result[28:] = ciphertext
    return bytes(result)

def fast_decrypt_with_master_key(ciphertext: bytes) -> bytes:
    """Optimized decryption with minimal memory allocations"""
    if len(ciphertext) < 28:
        raise ValueError("Invalid ciphertext length")
    
    # Direct slice access for speed
    nonce = ciphertext[:12]
    tag = ciphertext[12:28]
    actual_ciphertext = ciphertext[28:]
    
    cipher = Cipher(algorithms.AES(MASTER_KEY), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(actual_ciphertext) + decryptor.finalize()

def generate_hmac(key: bytes, data: bytes) -> bytes:
    """Generate HMAC-SHA256 for data integrity verification (optimized)"""
    # Use SHA256 instead of SHA512 for speed (still secure)
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

def verify_hmac(key: bytes, data: bytes, expected_hmac: bytes) -> bool:
    """Verify HMAC with constant-time comparison (optimized)"""
    try:
        actual_hmac = generate_hmac(key, data)
        return secrets.compare_digest(actual_hmac, expected_hmac)
    except Exception:
        return False

# Pre-compute HKDF info strings for speed
HKDF_INFO_HYBRID = b'ml-kem-1024-hybrid-enc-v1'
HKDF_INFO_HMAC = b'hmac-key-derivation-v1'

@app.route('/setup_guardians', methods=['POST'])
def api_setup_guardians():
    """API endpoint to setup guardians and create joint key."""
    try:
        print('called setup guardians call in the microservice')
        data = request.json
        number_of_guardians = safe_int_conversion(data['number_of_guardians'])
        quorum = safe_int_conversion(data['quorum'])
        party_names = data['party_names']
        candidate_names = data['candidate_names']
        
        print_json(data, "setup_guardians")
        print_data(data, "./io/setup_guardians_data.json")

        # Call service function
        result = setup_guardians_service(
            number_of_guardians,
            quorum,
            party_names,
            candidate_names
        )
        
        # Store election data
        election_data['guardians'] = result['guardians']
        election_data['joint_public_key'] = result['joint_public_key']
        election_data['commitment_hash'] = result['commitment_hash']
        election_data['manifest'] = create_election_manifest(party_names, candidate_names)
        election_data['number_of_guardians'] = result['number_of_guardians']
        election_data['quorum'] = result['quorum']
        
        # Convert response dicts to strings - all complex objects serialized
        response = {
            'status': 'success',
            'joint_public_key': result['joint_public_key'],
            'commitment_hash': result['commitment_hash'],
            'manifest': serialize_dict_to_string(to_raw(election_data['manifest'])),
            'guardian_data': serialize_list_of_dicts_to_list_of_strings(result['guardian_data']),
            'private_keys': serialize_list_of_dicts_to_list_of_strings(result['private_keys']),
            'public_keys': serialize_list_of_dicts_to_list_of_strings(result['public_keys']),
            'polynomials': serialize_list_of_dicts_to_list_of_strings(result['polynomials']),
            'number_of_guardians': result['number_of_guardians'],
            'quorum': result['quorum']
        }
        print_json(response, "setup_guardians_response")
        print_data(response, "./io/setup_guardians_response.json")
        print('Finished setup guardians call at the microservice')
        return jsonify(response), 200
    
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/create_encrypted_ballot', methods=['POST'])
def api_create_encrypted_ballot():
    """API endpoint to create and encrypt a ballot."""
    try:
        print('create encrypted ballot call at the microservice')
        data = request.json
        party_names = data['party_names']
        candidate_names = data['candidate_names']
        candidate_name = data['candidate_name']
        ballot_id = data['ballot_id']
        joint_public_key = data['joint_public_key']  # Expecting string
        commitment_hash = data['commitment_hash']    # Expecting string
        
        print_json(data, "create_encrypted_ballot")
        print_data(data, "./io/create_encrypted_ballot_request.json")

        # Get election data with safe int conversion
        number_of_guardians = safe_int_conversion(data.get('number_of_guardians', 1))
        quorum = safe_int_conversion(data.get('quorum', 1))
        
        # Call service function
        result = create_encrypted_ballot_service(
            party_names,
            candidate_names,
            candidate_name,
            ballot_id,
            joint_public_key,
            commitment_hash,
            number_of_guardians,
            quorum,
            create_plaintext_ballot,
            create_election_manifest,
            generate_ballot_hash_electionguard
        )
        
        # Store the encrypted ballot (optional) - ensure key exists
        if 'encrypted_ballots' not in election_data:
            election_data['encrypted_ballots'] = []
        election_data['encrypted_ballots'].append(result['encrypted_ballot'])
        
        response = {
            'status': 'success',
            'encrypted_ballot': result['encrypted_ballot'],
            'ballot_hash': result['ballot_hash']
        }
        print_json(response, "create_encrypted_ballot_response")
        print_data(response, "./io/create_encrypted_ballot_response.json")
        print('finished encrypting ballot at the microservice')
        return jsonify(response), 200
    
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/health', methods=['GET'])
def api_health_check():
    """API endpoint for health check."""
    return jsonify({'status': 'healthy'}), 200

@app.route('/create_encrypted_tally', methods=['POST'])
def api_create_encrypted_tally():
    """API endpoint to tally encrypted ballots."""
    try:
        print('call to create encrypted tally at teh microservice')
        data = request.json
        party_names = data['party_names']
        candidate_names = data['candidate_names']
        joint_public_key = data['joint_public_key']  # Expecting string
        commitment_hash = data['commitment_hash']    # Expecting string
        encrypted_ballots = data['encrypted_ballots'] # List of encrypted ballot strings
        
        print_json(data, "create_encrypted_tally")
        # Dump the request to a file named "create_encrypted_tally_request.json"
        print_data(data, "./io/create_encrypted_tally_request.json")

        # Get election data with safe int conversion
        number_of_guardians = safe_int_conversion(data.get('number_of_guardians', 1))
        quorum = safe_int_conversion(data.get('quorum', 1))
        
        # Call service function
        result = create_encrypted_tally_service(
            party_names,
            candidate_names,
            joint_public_key,
            commitment_hash,
            encrypted_ballots,
            number_of_guardians,
            quorum,
            create_election_manifest,
            ciphertext_tally_to_raw
        )
        
        # Optionally store tally data if needed
        election_data['ciphertext_tally'] = result['ciphertext_tally']
        election_data['submitted_ballots'] = result['submitted_ballots']
        
        response = {
            'status': 'success',
            'ciphertext_tally': serialize_dict_to_string(result['ciphertext_tally']),
            'submitted_ballots': serialize_list_of_dicts_to_list_of_strings(result['submitted_ballots'])
        }
        print_data(response, "./io/create_encrypted_tally_response.json")

        print_json(response, "create_encrypted_tally_response")
        print('finished craeting encrypted tally for the microservice')
        return jsonify(response), 200
    
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/create_partial_decryption', methods=['POST'])
def api_create_partial_decryption():
    """API endpoint to compute decryption shares for a single guardian."""
    try:
        print('call to create partialdecryptions at the microservice')
        data = request.json
        guardian_id = data['guardian_id']
        print_json(data, "create_partial_decryption")
        # Print the request body as JSON to a file named "partial_decryption_request.json"

        print_data(data, "./io/partial_decryption_request.json")

        # Deserialize single guardian data from string (if available)
        guardian_data = None
        if data.get('guardian_data'):
            try:
                guardian_data = deserialize_string_to_dict(data['guardian_data'])
            except Exception as e:
                raise ValueError(f"Error deserializing guardian_data: {e}")
            
        try:
            private_key = deserialize_string_to_dict(data['private_key'])
        except Exception as e:
            raise ValueError(f"Error deserializing private_key: {e}")
            
        try:
            public_key = deserialize_string_to_dict(data['public_key'])
        except Exception as e:
            raise ValueError(f"Error deserializing public_key: {e}")
            
        # Polynomial is no longer required from the request
        # We'll create a minimal polynomial internally if needed
        party_names = data['party_names']
        candidate_names = data['candidate_names']
        
        # Deserialize dict from string with error context
        try:
            ciphertext_tally_json = deserialize_string_to_dict(data['ciphertext_tally'])
        except Exception as e:
            raise ValueError(f"Error deserializing ciphertext_tally: {e}")
            
        # Deserialize submitted_ballots from list of strings to list of dicts
        try:
            submitted_ballots_json = deserialize_list_of_strings_to_list_of_dicts(data['submitted_ballots'])
        except Exception as e:
            raise ValueError(f"Error deserializing submitted_ballots: {e}")
            
        joint_public_key = data['joint_public_key']
        commitment_hash = data['commitment_hash']
        
        # Get election data with safe int conversion
        number_of_guardians = safe_int_conversion(data.get('number_of_guardians', 1))
        quorum = safe_int_conversion(data.get('quorum', 1))
        
        # Call service function with single guardian data
        result = create_partial_decryption_service(
            party_names,
            candidate_names,
            guardian_id,
            guardian_data,
            private_key,
            public_key,
            None,  # polynomial no longer required
            ciphertext_tally_json,
            submitted_ballots_json,
            joint_public_key,
            commitment_hash,
            number_of_guardians,
            quorum,
            create_election_manifest,
            raw_to_ciphertext_tally,
            compute_ballot_shares
        )
        
        response = {
            'status': 'success',
            'guardian_public_key': result['guardian_public_key'],
            'tally_share': result['tally_share'],
            'ballot_shares': serialize_dict_to_string(result['ballot_shares'])
        }
        print_data(response, "./io/create_partial_decryption_response.json")

        print_json(response, "create_partial_decryption_response")
        print('finished creating partial decryption at the microservice')
        return jsonify(response), 200
    
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/create_compensated_decryption', methods=['POST'])
def api_create_compensated_decryption():
    """API endpoint to compute compensated decryption shares for missing guardians."""
    try:
        # Extract data from request
        print('call to create compensated decryption at the microservice')
        data = request.json
        available_guardian_id = data['available_guardian_id']
        missing_guardian_id = data['missing_guardian_id']
        print_json(data, "create_compensated_decryption")
        # Dump the request to a file named "create_compensated_decryption_request.json"
        print_data(data, "./io/create_compensated_decryption_request.json")

        # Deserialize single guardian data from strings
        try:
            available_guardian_data = deserialize_string_to_dict(data['available_guardian_data'])
        except Exception as e:
            raise ValueError(f"Error deserializing available_guardian_data: {e}")
            
        try:
            missing_guardian_data = deserialize_string_to_dict(data['missing_guardian_data'])
        except Exception as e:
            raise ValueError(f"Error deserializing missing_guardian_data: {e}")
            
        try:
            available_private_key = deserialize_string_to_dict(data['available_private_key'])
        except Exception as e:
            raise ValueError(f"Error deserializing available_private_key: {e}")
            
        try:
            available_public_key = deserialize_string_to_dict(data['available_public_key'])
        except Exception as e:
            raise ValueError(f"Error deserializing available_public_key: {e}")
            
        try:
            available_polynomial = deserialize_string_to_dict(data['available_polynomial'])
        except Exception as e:
            raise ValueError(f"Error deserializing available_polynomial: {e}")
            
        party_names = data['party_names']
        candidate_names = data['candidate_names']
        
        # Deserialize dict from string with error context
        try:
            ciphertext_tally_json = deserialize_string_to_dict(data['ciphertext_tally'])
        except Exception as e:
            raise ValueError(f"Error deserializing ciphertext_tally: {e}")
            
        # Deserialize submitted_ballots from list of strings to list of dicts
        try:
            submitted_ballots_json = deserialize_list_of_strings_to_list_of_dicts(data['submitted_ballots'])
        except Exception as e:
            raise ValueError(f"Error deserializing submitted_ballots: {e}")
        joint_public_key = data['joint_public_key']
        commitment_hash = data['commitment_hash']
        
        # Get election data with safe int conversion
        number_of_guardians = safe_int_conversion(data.get('number_of_guardians', 1))
        quorum = safe_int_conversion(data.get('quorum', 1))
        
        # Call service function
        result = create_compensated_decryption_service(
            party_names,
            candidate_names,
            available_guardian_id,
            missing_guardian_id,
            available_guardian_data,
            missing_guardian_data,
            available_private_key,
            available_public_key,
            available_polynomial,
            ciphertext_tally_json,
            submitted_ballots_json,
            joint_public_key,
            commitment_hash,
            number_of_guardians,
            quorum,
            create_election_manifest,
            raw_to_ciphertext_tally,
            compute_compensated_ballot_shares
        )

        # Format response
        response = {
            'status': 'success',
            'compensated_tally_share': result['compensated_tally_share'],
            'compensated_ballot_shares': serialize_dict_to_string(result['compensated_ballot_shares'])
        }
        print_data(response, "./io/create_compensated_decryption_response.json")
        print('finished creating compensated decryption at the microservice')
        return jsonify(response), 200
    
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
        


@app.route('/combine_decryption_shares', methods=['POST'])
def api_combine_decryption_shares():
    """API endpoint to combine decryption shares with quorum support."""
    try:
        # Extract data from request

        data = request.json
        party_names = data['party_names']
        candidate_names = data['candidate_names']
        joint_public_key = data['joint_public_key']
        commitment_hash = data['commitment_hash']
        print_json(data, "combine_decryption_shares")
        print_data(data, "./io/combine_decryption_shares_request.json")
        # Deserialize dict from string with error context
        try:
            ciphertext_tally_json = deserialize_string_to_dict(data['ciphertext_tally'])
        except Exception as e:
            raise ValueError(f"Error deserializing ciphertext_tally: {e}")
        
        # Deserialize list of strings to list of dicts for submitted_ballots
        try:
            submitted_ballots_json = deserialize_list_of_strings_to_list_of_dicts(data['submitted_ballots'])
        except Exception as e:
            raise ValueError(f"Error deserializing submitted_ballots: {e}")
        
        # Deserialize guardian_data from list of strings to list of dicts
        try:
            guardian_data = deserialize_list_of_strings_to_list_of_dicts(data['guardian_data'])
        except Exception as e:
            raise ValueError(f"Error deserializing guardian_data: {e}")

        # Reconstruct available_guardian_shares from separate arrays
        available_guardian_shares = {}
        available_guardian_ids_list = data.get('available_guardian_ids', [])
        available_guardian_public_keys = data.get('available_guardian_public_keys', [])
        available_tally_shares = data.get('available_tally_shares', [])
        available_ballot_shares = data.get('available_ballot_shares', [])
        
        for i, guardian_id in enumerate(available_guardian_ids_list):
            try:
                available_guardian_shares[guardian_id] = {
                    'guardian_public_key': available_guardian_public_keys[i],
                    'tally_share': available_tally_shares[i],
                    'ballot_shares': deserialize_string_to_dict(available_ballot_shares[i]) if isinstance(available_ballot_shares[i], str) else available_ballot_shares[i]
                }
            except Exception as e:
                raise ValueError(f"Error reconstructing available_guardian_shares for {guardian_id}: {e}")
        
        # Reconstruct compensated_shares from separate arrays
        all_compensated_shares = {}
        missing_guardian_ids_list = data.get('missing_guardian_ids', [])
        compensating_guardian_ids_list = data.get('compensating_guardian_ids', [])
        compensated_tally_shares = data.get('compensated_tally_shares', [])
        compensated_ballot_shares = data.get('compensated_ballot_shares', [])
        
        for i in range(len(missing_guardian_ids_list)):
            try:
                missing_guardian_id = missing_guardian_ids_list[i]
                compensating_guardian_id = compensating_guardian_ids_list[i]
                
                if missing_guardian_id not in all_compensated_shares:
                    all_compensated_shares[missing_guardian_id] = {}
                
                all_compensated_shares[missing_guardian_id][compensating_guardian_id] = {
                    'compensated_tally_share': compensated_tally_shares[i],
                    'compensated_ballot_shares': deserialize_string_to_dict(compensated_ballot_shares[i]) if isinstance(compensated_ballot_shares[i], str) else compensated_ballot_shares[i]
                }
            except Exception as e:
                raise ValueError(f"Error reconstructing compensated_shares: {e}")
        
        # Get the required quorum with safe int conversion
        quorum = safe_int_conversion(data.get('quorum', len(guardian_data)))
        number_of_guardians = safe_int_conversion(data.get('number_of_guardians', len(guardian_data)))
        
        # Determine which guardians are available and which are missing
        available_guardian_ids = set(available_guardian_shares.keys())
        all_guardian_ids = {g['id'] for g in guardian_data}
        missing_guardian_ids = all_guardian_ids - available_guardian_ids
        
        print(f"Available guardians: {sorted(available_guardian_ids)}")
        print(f"Missing guardians: {sorted(missing_guardian_ids)}")
        print(f"All guardian IDs: {sorted(all_guardian_ids)}")
        print(f"Quorum required: {quorum}, Available: {len(available_guardian_ids)}")
        
        # Validate we have enough guardians
        if len(available_guardian_ids) < quorum:
            raise ValueError(f"Insufficient guardians available. Need {quorum}, have {len(available_guardian_ids)}")
        
        # Filter compensated shares to ONLY include the missing guardians
        # This is where the backend determines which guardians need compensation
        filtered_compensated_shares = {}
        for missing_guardian_id in missing_guardian_ids:
            if missing_guardian_id in all_compensated_shares:
                filtered_compensated_shares[missing_guardian_id] = all_compensated_shares[missing_guardian_id]
                print(f"Including compensated shares for missing guardian: {missing_guardian_id}")
            else:
                raise ValueError(f"Missing compensated shares for guardian {missing_guardian_id}")
        
        # Log what we're filtering out
        excluded_guardians = set(all_compensated_shares.keys()) - missing_guardian_ids
        if excluded_guardians:
            print(f"Excluding compensated shares for available guardians: {sorted(excluded_guardians)}")
        
        # Call service function
        results = combine_decryption_shares_service(
            party_names,
            candidate_names,
            joint_public_key,
            commitment_hash,
            ciphertext_tally_json,
            submitted_ballots_json,
            guardian_data,
            available_guardian_shares,
            filtered_compensated_shares,
            quorum,
            create_election_manifest,
            raw_to_ciphertext_tally,
            generate_ballot_hash,
            generate_ballot_hash_electionguard
        )
        
        # Format response - ensure all nested dicts are serialized to strings
        response = {
            'status': 'success',
            'results': serialize_dict_to_string(results)
        }
        print_json(response, "combine_decryption_shares_response")
        print_data(response, "./io/combine_decryption_shares_response.json")
        return jsonify(response), 200
    
    except ValueError as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/encrypt', methods=['POST'])
@rate_limit(max_requests=10, window_minutes=1)
def encrypt_it():
    """
    Encrypt endpoint with quantum-resistant encryption and HMAC protection (optimized)
    
    Returns:
    - encrypted_data: The encrypted private key (Storage 1)
    - credentials: Contains all metadata + HMAC tag (Storage 2)
    """
    if not PQ_AVAILABLE:
        logger.error("Post-quantum cryptography not available")
        return jsonify({'error': 'Post-quantum cryptography not available'}), 501

    data = request.get_json()
    validation_error = validate_input(data, ['private_key'])
    if validation_error:
        logger.warning(f"Validation error: {validation_error}")
        return jsonify({'error': validation_error}), 400

    try:
        # Input validation (optimized)
        private_key = data['private_key']
        if not isinstance(private_key, str) or len(private_key) > 5000:
            return jsonify({'error': 'Invalid private key format or size'}), 400

        # Generate optimized password and salt
        password = generate_strong_password()
        salt = os.urandom(SCRYPT_SALT_LENGTH)
        
        # Post-quantum operations (these are the fastest part)
        pq_public_key, pq_private_key = generate_keypair()
        pq_ciphertext, pq_shared_secret = encrypt(pq_public_key)
        
        # Optimized key derivation
        password_key = derive_key_from_password(password, salt)
        combined_key = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_LENGTH,
            salt=salt,
            info=HKDF_INFO_HYBRID,
            backend=default_backend()
        ).derive(password_key + pq_shared_secret)

        # Fast encryption of private key
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(combined_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        
        private_key_bytes = private_key.encode('utf-8')
        encrypted_data = encryptor.update(private_key_bytes) + encryptor.finalize()

        # Fast password encryption
        encrypted_password = fast_encrypt_with_master_key(password.encode('utf-8'))

        # Create credentials structure (without HMAC tag first)
        credentials_data = {
            'version': '1.0',
            'algorithm': PQ_ALGORITHM,
            'salt': base64.b64encode(salt).decode(),
            'pq_private_key': base64.b64encode(pq_private_key).decode(),
            'pq_ciphertext': base64.b64encode(pq_ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'tag': base64.b64encode(encryptor.tag).decode(),
            'encrypted_password': base64.b64encode(encrypted_password).decode()
        }
        
        # Serialize credentials for HMAC calculation
        credentials_json = json.dumps(credentials_data, separators=(',', ':')).encode('utf-8')
        
        # Generate HMAC for credentials integrity
        hmac_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=HKDF_INFO_HMAC,
            backend=default_backend()
        ).derive(combined_key)
        
        hmac_tag = generate_hmac(hmac_key, credentials_json)
        
        # Add HMAC tag to credentials
        credentials_data['hmac_tag'] = base64.b64encode(hmac_tag).decode()
        
        # Final credentials with HMAC tag
        final_credentials = json.dumps(credentials_data, separators=(',', ':')).encode('utf-8')

        logger.info(f"Successful encryption for IP: {request.remote_addr}")
        
        # Return only 2 storage items instead of 3
        return jsonify({
            'status': 'success',
            'encrypted_data': base64.b64encode(encrypted_data).decode(),  # Storage 1
            'credentials': base64.b64encode(final_credentials).decode()    # Storage 2 (includes HMAC)
        }), 200

    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

@app.route('/api/decrypt', methods=['POST'])
@rate_limit(max_requests=10, window_minutes=1)
def decrypt_it():
    """
    Decrypt endpoint with HMAC verification and quantum-safe decryption (optimized)
    
    Expects:
    - encrypted_data: The encrypted private key (from Storage 1)
    - credentials: Contains all metadata + HMAC tag (from Storage 2)
    """
    if not PQ_AVAILABLE:
        logger.error("Post-quantum cryptography not available")
        return jsonify({'error': 'Post-quantum cryptography not available'}), 501

    data = request.get_json()
    validation_error = validate_input(data, ['encrypted_data', 'credentials'])
    if validation_error:
        logger.warning(f"Validation error: {validation_error}")
        return jsonify({'error': validation_error}), 400

    try:
        # Fast decode and parse credentials
        credentials_json = base64.b64decode(data['credentials'])
        credentials = json.loads(credentials_json.decode('utf-8'))
        
        # Version check
        if credentials.get('version') != '1.0':
            return jsonify({'error': 'Unsupported credential version'}), 400
        
        # Extract HMAC tag from credentials
        if 'hmac_tag' not in credentials:
            return jsonify({'error': 'Missing HMAC tag in credentials'}), 400
        
        hmac_tag = base64.b64decode(credentials['hmac_tag'])
        
        # Create credentials without HMAC tag for verification
        credentials_for_verification = {k: v for k, v in credentials.items() if k != 'hmac_tag'}
        credentials_for_verification_json = json.dumps(credentials_for_verification, separators=(',', ':')).encode('utf-8')
        
        # Fast parameter extraction
        salt = base64.b64decode(credentials['salt'])
        pq_private_key = base64.b64decode(credentials['pq_private_key'])
        pq_ciphertext = base64.b64decode(credentials['pq_ciphertext'])
        
        # Post-quantum decryption
        pq_shared_secret = decrypt(pq_private_key, pq_ciphertext)
        
        # Fast password decryption
        encrypted_password = base64.b64decode(credentials['encrypted_password'])
        password = fast_decrypt_with_master_key(encrypted_password).decode('utf-8')
        
        # Reconstruct combined key
        password_key = derive_key_from_password(password, salt)
        combined_key = HKDF(
            algorithm=hashes.SHA256(),
            length=AES_KEY_LENGTH,
            salt=salt,
            info=HKDF_INFO_HYBRID,
            backend=default_backend()
        ).derive(password_key + pq_shared_secret)
        
        # Verify HMAC integrity of credentials
        hmac_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=HKDF_INFO_HMAC,
            backend=default_backend()
        ).derive(combined_key)
        
        if not verify_hmac(hmac_key, credentials_for_verification_json, hmac_tag):
            logger.warning(f"HMAC verification failed for IP: {request.remote_addr}")
            return jsonify({'error': 'Authentication failed - credentials tampered'}), 403

        # Fast decryption of private key
        nonce = base64.b64decode(credentials['nonce'])
        tag = base64.b64decode(credentials['tag'])
        encrypted_data = base64.b64decode(data['encrypted_data'])
        
        cipher = Cipher(algorithms.AES(combined_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        logger.info(f"Successful decryption for IP: {request.remote_addr}")
        
        return jsonify({
            'status': 'success',
            'private_key': decrypted_data.decode('utf-8')
        }), 200

    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Decryption failed'}), 400

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'pq_available': PQ_AVAILABLE,
        'algorithm': PQ_ALGORITHM if PQ_AVAILABLE else None,
        'storage_design': '2-storage (encrypted_data + credentials_with_hmac)'
    }), 200

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'Request too large'}), 413

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({'error': 'Rate limit exceeded'}), 429

if __name__ == '__main__':
    if not PQ_AVAILABLE:
        print("Warning: Running without post-quantum cryptography support")
    
    # Security headers
    @app.after_request
    def after_request(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response
    
    print("Starting development server with enhanced security and 2-storage design...")
    print("IMPORTANT: Use proper WSGI server and SSL certificates in production!")
    print("Storage Design: encrypted_data (Storage 1) + credentials_with_hmac (Storage 2)")
    
    app.run(host='0.0.0.0', port=5000, debug=True)