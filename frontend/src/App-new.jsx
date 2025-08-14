import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Navigation from './components/Navigation';
import Home from './components/Home';
import SetupGuardians from './services/SetupGuardians';
import CreateEncryptedBallot from './services/CreateEncryptedBallot';
import CreateEncryptedTally from './services/CreateEncryptedTally';
import PartialDecryption from './services/PartialDecryption';
import CompensatedDecryption from './services/CompensatedDecryption';
import CombineDecryptionShares from './services/CombineDecryptionShares';
import './App.css';

function App() {
  const [pyodide, setPyodide] = useState(null);
  const [pyodideLoading, setPyodideLoading] = useState(true);

  useEffect(() => {
    initializePyodide();
  }, []);

  const initializePyodide = async () => {
    try {
      setPyodideLoading(true);
      console.log('Loading Pyodide...');
      
      // Load Pyodide from CDN directly
      const pyodideInstance = await window.loadPyodide({
        indexURL: "https://cdn.jsdelivr.net/pyodide/v0.24.1/full/",
      });
      
      console.log('Pyodide loaded successfully');
      
      // Load comprehensive Python service code for all ElectionGuard services
      const pythonCode = `
"""
ElectionGuard services for browser-based cryptographic operations.
This module contains simplified versions of all ElectionGuard functions
optimized for running in Pyodide.
"""

import json
import hashlib
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any

# ========== CREATE ENCRYPTED BALLOT SERVICE ==========

def create_plaintext_ballot(party_names, candidate_names, candidate_name, ballot_id):
    """Create a single plaintext ballot for a specific candidate."""
    if candidate_name not in candidate_names:
        raise ValueError(f"Candidate {candidate_name} not found in candidate list")
    
    ballot = {
        "object_id": ballot_id,
        "style_id": "ballot-style-1",
        "contests": [{
            "object_id": "contest-1",
            "ballot_selections": []
        }]
    }
    
    # Create selections for each candidate
    for i, candidate in enumerate(candidate_names):
        vote = 1 if candidate == candidate_name else 0
        selection = {
            "object_id": candidate,
            "vote": vote,
            "is_placeholder_selection": False
        }
        ballot["contests"][0]["ballot_selections"].append(selection)
    
    return ballot

def simulate_encryption(plaintext_ballot, joint_public_key, commitment_hash):
    """Simulate ballot encryption for demonstration purposes."""
    encrypted_ballot = {
        "object_id": plaintext_ballot["object_id"],
        "style_id": plaintext_ballot["style_id"],
        "manifest_hash": str(commitment_hash),
        "code_seed": str(hash(f"{plaintext_ballot['object_id']}{joint_public_key}")),
        "contests": []
    }
    
    for contest in plaintext_ballot["contests"]:
        encrypted_contest = {
            "object_id": contest["object_id"],
            "sequence_order": 0,
            "description_hash": hashlib.sha256(contest["object_id"].encode()).hexdigest(),
            "ballot_selections": []
        }
        
        for selection in contest["ballot_selections"]:
            encrypted_selection = {
                "object_id": selection["object_id"],
                "sequence_order": 0,
                "description_hash": hashlib.sha256(selection["object_id"].encode()).hexdigest(),
                "ciphertext": {
                    "pad": str(int(joint_public_key) * selection["vote"] + hash(selection["object_id"])),
                    "data": str(int(joint_public_key) * selection["vote"] * 2 + hash(f"{selection['object_id']}_data"))
                },
                "crypto_hash": hashlib.sha256(f"{selection['object_id']}{selection['vote']}{joint_public_key}".encode()).hexdigest(),
                "is_placeholder_selection": selection["is_placeholder_selection"]
            }
            encrypted_contest["ballot_selections"].append(encrypted_selection)
        
        encrypted_ballot["contests"].append(encrypted_contest)
    
    return encrypted_ballot

def process_create_encrypted_ballot_request(json_input):
    """Process create encrypted ballot requests."""
    try:
        data = json.loads(json_input)
        
        party_names = data.get('party_names', [])
        candidate_names = data.get('candidate_names', [])
        candidate_name = data.get('candidate_name', '')
        ballot_id = data.get('ballot_id', str(uuid.uuid4()))
        joint_public_key = data.get('joint_public_key', '12345')
        commitment_hash = data.get('commitment_hash', '67890')
        
        if not party_names or not candidate_names or not candidate_name:
            raise ValueError("Missing required parameters")
        
        if candidate_name not in candidate_names:
            raise ValueError(f"Candidate '{candidate_name}' not found in candidate list")
        
        ballot = create_plaintext_ballot(party_names, candidate_names, candidate_name, ballot_id)
        encrypted_ballot = simulate_encryption(ballot, joint_public_key, commitment_hash)
        ballot_hash = hashlib.sha256(json.dumps(encrypted_ballot, sort_keys=True).encode()).hexdigest()
        
        result = {
            'encrypted_ballot': encrypted_ballot,
            'ballot_hash': ballot_hash,
            'status': 'success',
            'plaintext_ballot': ballot
        }
        
        return json.dumps(result)
        
    except Exception as e:
        return json.dumps({'status': 'error', 'error': str(e)})

# ========== SETUP GUARDIANS SERVICE ==========

def process_setup_guardians_request(json_input):
    """Process setup guardians requests."""
    try:
        data = json.loads(json_input)
        
        number_of_guardians = data.get('number_of_guardians', 3)
        quorum = data.get('quorum', 2)
        
        if quorum > number_of_guardians:
            raise ValueError("Quorum cannot be greater than number of guardians")
        
        guardians = []
        for i in range(number_of_guardians):
            guardian = {
                "id": f"guardian-{i+1}",
                "sequence_order": i,
                "key_pair": {
                    "public_key": str(hash(f"guardian-{i+1}-public") % 10**20),
                    "secret_key": str(hash(f"guardian-{i+1}-secret") % 10**20)
                },
                "election_partial_key_backup": {
                    f"guardian-{j+1}": str(hash(f"guardian-{i+1}-backup-{j+1}") % 10**15)
                    for j in range(number_of_guardians) if j != i
                }
            }
            guardians.append(guardian)
        
        joint_public_key = str(sum(int(g["key_pair"]["public_key"]) for g in guardians) % 10**20)
        
        result = {
            'guardians': guardians,
            'joint_public_key': joint_public_key,
            'commitment_hash': str(hash(joint_public_key) % 10**15),
            'status': 'success'
        }
        
        return json.dumps(result)
        
    except Exception as e:
        return json.dumps({'status': 'error', 'error': str(e)})

# ========== CREATE ENCRYPTED TALLY SERVICE ==========

def process_create_encrypted_tally_request(json_input):
    """Process create encrypted tally requests."""
    try:
        data = json.loads(json_input)
        
        encrypted_ballots = data.get('encrypted_ballots', [])
        
        if not encrypted_ballots:
            raise ValueError("No encrypted ballots provided")
        
        # Simulate tally creation by aggregating ballot data
        tally = {
            "object_id": "election-tally",
            "contests": {}
        }
        
        for ballot in encrypted_ballots:
            for contest in ballot.get('contests', []):
                contest_id = contest.get('object_id', 'unknown')
                if contest_id not in tally['contests']:
                    tally['contests'][contest_id] = {
                        "object_id": contest_id,
                        "selections": {}
                    }
                
                for selection in contest.get('ballot_selections', []):
                    selection_id = selection.get('object_id', 'unknown')
                    if selection_id not in tally['contests'][contest_id]['selections']:
                        tally['contests'][contest_id]['selections'][selection_id] = {
                            "object_id": selection_id,
                            "ciphertext": {"pad": "0", "data": "0"}
                        }
                    
                    # Simulate homomorphic addition
                    current_pad = int(tally['contests'][contest_id]['selections'][selection_id]['ciphertext']['pad'])
                    current_data = int(tally['contests'][contest_id]['selections'][selection_id]['ciphertext']['data'])
                    
                    new_pad = int(selection.get('ciphertext', {}).get('pad', '0'))
                    new_data = int(selection.get('ciphertext', {}).get('data', '0'))
                    
                    tally['contests'][contest_id]['selections'][selection_id]['ciphertext']['pad'] = str(current_pad + new_pad)
                    tally['contests'][contest_id]['selections'][selection_id]['ciphertext']['data'] = str(current_data + new_data)
        
        result = {
            'encrypted_tally': tally,
            'hash': hashlib.sha256(json.dumps(tally, sort_keys=True).encode()).hexdigest(),
            'status': 'success'
        }
        
        return json.dumps(result)
        
    except Exception as e:
        return json.dumps({'status': 'error', 'error': str(e)})

# ========== PARTIAL DECRYPTION SERVICE ==========

def process_partial_decryption_request(json_input):
    """Process partial decryption requests."""
    try:
        data = json.loads(json_input)
        
        encrypted_tally = data.get('encrypted_tally', {})
        guardian_id = data.get('guardian_id', 'guardian-1')
        
        if not encrypted_tally:
            raise ValueError("No encrypted tally provided")
        
        partial_decryptions = {}
        
        for contest_id, contest in encrypted_tally.get('contests', {}).items():
            partial_decryptions[contest_id] = {}
            
            for selection_id, selection in contest.get('selections', {}).items():
                # Simulate partial decryption
                ciphertext_pad = int(selection.get('ciphertext', {}).get('pad', '0'))
                partial_decrypt_value = str(ciphertext_pad // 2)  # Simplified partial decryption
                
                partial_decryptions[contest_id][selection_id] = {
                    "guardian_id": guardian_id,
                    "partial_decryption": partial_decrypt_value,
                    "proof": {
                        "pad": str(hash(f"{guardian_id}-proof-pad") % 10**10),
                        "data": str(hash(f"{guardian_id}-proof-data") % 10**10)
                    }
                }
        
        result = {
            'partial_decryptions': partial_decryptions,
            'guardian_id': guardian_id,
            'status': 'success'
        }
        
        return json.dumps(result)
        
    except Exception as e:
        return json.dumps({'status': 'error', 'error': str(e)})

# ========== COMPENSATED DECRYPTION SERVICE ==========

def process_compensated_decryption_request(json_input):
    """Process compensated decryption requests."""
    try:
        data = json.loads(json_input)
        
        encrypted_tally = data.get('encrypted_tally', {})
        missing_guardians = data.get('missing_guardians', [])
        available_guardians = data.get('available_guardians', [])
        
        compensated_shares = {}
        
        for missing_guardian in missing_guardians:
            compensated_shares[missing_guardian] = {}
            
            for contest_id, contest in encrypted_tally.get('contests', {}).items():
                compensated_shares[missing_guardian][contest_id] = {}
                
                for selection_id, selection in contest.get('selections', {}).items():
                    # Simulate compensated decryption share
                    compensated_value = str(hash(f"{missing_guardian}-{contest_id}-{selection_id}") % 10**10)
                    
                    compensated_shares[missing_guardian][contest_id][selection_id] = {
                        "missing_guardian_id": missing_guardian,
                        "compensated_decryption": compensated_value,
                        "recovery_proof": {
                            "pad": str(hash(f"recovery-{missing_guardian}-pad") % 10**10),
                            "data": str(hash(f"recovery-{missing_guardian}-data") % 10**10)
                        }
                    }
        
        result = {
            'compensated_decryption_shares': compensated_shares,
            'missing_guardians': missing_guardians,
            'status': 'success'
        }
        
        return json.dumps(result)
        
    except Exception as e:
        return json.dumps({'status': 'error', 'error': str(e)})

# ========== COMBINE DECRYPTION SHARES SERVICE ==========

def process_combine_decryption_shares_request(json_input):
    """Process combine decryption shares requests."""
    try:
        data = json.loads(json_input)
        
        encrypted_tally = data.get('encrypted_tally', {})
        decryption_shares = data.get('decryption_shares', {})
        
        if not encrypted_tally or not decryption_shares:
            raise ValueError("Missing required parameters: encrypted_tally and decryption_shares")
        
        plaintext_tally = {
            "object_id": encrypted_tally.get('object_id', 'decrypted-tally'),
            "contests": {}
        }
        
        for contest_id, contest in encrypted_tally.get('contests', {}).items():
            plaintext_tally['contests'][contest_id] = {
                "object_id": contest_id,
                "selections": {}
            }
            
            for selection_id, selection in contest.get('selections', {}).items():
                # Simulate combining shares to get plaintext tally
                combined_value = 0
                
                # Use shares from different guardians
                for guardian_id, shares in decryption_shares.items():
                    if contest_id in shares and selection_id in shares[contest_id]:
                        partial_value = int(shares[contest_id][selection_id].get('partial_decryption', '0'))
                        combined_value += partial_value
                
                # Simulate final decryption (simplified)
                plaintext_value = combined_value % 100  # Keep reasonable for demo
                
                plaintext_tally['contests'][contest_id]['selections'][selection_id] = {
                    "object_id": selection_id,
                    "tally": plaintext_value,
                    "message": {
                        "pad": str(hash(f"final-{selection_id}-pad") % 10**8),
                        "data": str(hash(f"final-{selection_id}-data") % 10**8)
                    }
                }
        
        result = {
            'plaintext_tally': plaintext_tally,
            'hash': hashlib.sha256(json.dumps(plaintext_tally, sort_keys=True).encode()).hexdigest(),
            'status': 'success'
        }
        
        return json.dumps(result)
        
    except Exception as e:
        return json.dumps({'status': 'error', 'error': str(e)})

# ========== GENERIC HANDLER ==========

def process_generic_request(json_input, service_name):
    """Generic handler for services that don't have specific implementations yet."""
    try:
        data = json.loads(json_input)
        
        result = {
            'service': service_name,
            'input_received': data,
            'message': f'Service {service_name} processed successfully (simulated)',
            'hash': hashlib.sha256(json_input.encode()).hexdigest(),
            'status': 'success'
        }
        
        return json.dumps(result)
        
    except Exception as e:
        return json.dumps({'status': 'error', 'error': str(e)})
`;
      
      console.log('Loading Python service code...');
      await pyodideInstance.runPython(pythonCode);
      
      console.log('Python services loaded successfully');
      setPyodide(pyodideInstance);
      setPyodideLoading(false);
    } catch (err) {
      console.error('Failed to initialize Pyodide:', err);
      setPyodideLoading(false);
    }
  };

  if (pyodideLoading) {
    return (
      <div className="app">
        <div className="loading">
          <h2>Loading ElectionGuard Frontend...</h2>
          <p>Initializing Python environment with Pyodide...</p>
          <p>This may take a moment on first load.</p>
        </div>
      </div>
    );
  }

  return (
    <Router>
      <div className="app">
        <Navigation />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/setup-guardians" element={<SetupGuardians pyodide={pyodide} />} />
            <Route path="/create-encrypted-ballot" element={<CreateEncryptedBallot pyodide={pyodide} />} />
            <Route path="/create-encrypted-tally" element={<CreateEncryptedTally pyodide={pyodide} />} />
            <Route path="/partial-decryption" element={<PartialDecryption pyodide={pyodide} />} />
            <Route path="/compensated-decryption" element={<CompensatedDecryption pyodide={pyodide} />} />
            <Route path="/combine-decryption-shares" element={<CombineDecryptionShares pyodide={pyodide} />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;
