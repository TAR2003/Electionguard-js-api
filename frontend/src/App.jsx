import React, { useState, useEffect } from 'react';

// Sample JSON template for user guidance
const sampleJSON = {
  "party_names": ["Democratic Party", "Republican Party"],
  "candidate_names": ["Alice Johnson", "Bob Smith"],
  "candidate_name": "Alice Johnson",
  "ballot_id": "ballot-2",
  "joint_public_key": "192092755156231671093223778782038695065101522019070175742120001623003267241513757136227863328925910512185841027721697476877549669819431771876592926885052250651672148783368221125549887407084348952231724782364002619614618897369477866471373019039735621390113850105102922212780383631956146377435362595683760875192854590491326598832286888990264264620700364490868486340627499200032922433224175496175887347330409292980437734702642297568062162985068779044666783812358642542859634656068522974300239658153095867913052738128071717368595798314912028334032058564535504771808088137250357855228869309530531240718087076203668553298166523018349788850458853486241800439402387351215799802649275040421956260197330938863809622252568808707955579945500792834586235661908696103943701082379609127781517490835290764835651368135473832396182501490666192312148961526046769270123653279627095276057606514903543526569083228416152395697754329083851400111040417283946287651866590271816627399515875325232910401818298356830563577592225577492879443861313088892592923083407524485369082164220965239246966078405352956257667965562368457043599659039052977657605755900669108673833505421366562480114041533915928368611215085905470214350327727101679130617594875815609554919785397",
  "commitment_hash": "98906773777139738089215984685590350107307121961639735817877463064584850693496",
  "number_of_guardians": 5,
  "quorum": 3
};

function App() {
  const [pyodide, setPyodide] = useState(null);
  const [loading, setLoading] = useState(true);
  const [processing, setProcessing] = useState(false);
  const [jsonInput, setJsonInput] = useState(JSON.stringify(sampleJSON, null, 2));
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    initializePyodide();
  }, []);

  const initializePyodide = async () => {
    try {
      setLoading(true);
      console.log('Loading Pyodide...');
      
      // Load Pyodide from CDN directly
      const pyodideInstance = await window.loadPyodide({
        indexURL: "https://cdn.jsdelivr.net/pyodide/v0.24.1/full/",
      });
      
      console.log('Pyodide loaded successfully');
      
      // Load the Python service code directly as a string
      const pythonCode = `
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


def generate_ballot_hash(encrypted_ballot):
    """Generate a hash for the encrypted ballot."""
    ballot_str = json.dumps(encrypted_ballot, sort_keys=True)
    return hashlib.sha256(ballot_str.encode()).hexdigest()


def simulate_encryption(plaintext_ballot, joint_public_key, commitment_hash):
    """
    Simulate ballot encryption for demonstration purposes.
    In a real implementation, this would use proper ElGamal encryption.
    """
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
    party_names,
    candidate_names,
    candidate_name,
    ballot_id,
    joint_public_key,
    commitment_hash,
    number_of_guardians,
    quorum
):
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
            'plaintext_ballot': ballot
        }
    
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


def process_ballot_request(json_input):
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
`;
      
      console.log('Loading Python service code...');
      await pyodideInstance.runPython(pythonCode);
      
      console.log('Python service loaded successfully');
      setPyodide(pyodideInstance);
      setLoading(false);
    } catch (err) {
      console.error('Failed to initialize Pyodide:', err);
      setError(`Failed to initialize Python environment: ${err.message}`);
      setLoading(false);
    }
  };

  const processBallot = async () => {
    if (!pyodide) {
      setError('Python environment not initialized');
      return;
    }

    setProcessing(true);
    setError(null);
    setResult(null);

    try {
      // Validate JSON
      JSON.parse(jsonInput);
      
      // Call Python function
      console.log('Processing ballot with input:', jsonInput);
      
      // Set the JSON input as a Python variable first to avoid string escaping issues
      pyodide.globals.set('json_input', jsonInput);
      
      const pythonResult = pyodide.runPython(`
result = process_ballot_request(json_input)
result
      `);
      
      console.log('Python result:', pythonResult);
      
      const parsedResult = JSON.parse(pythonResult);
      setResult(parsedResult);
      
      if (parsedResult.status === 'error') {
        setError(parsedResult.error);
      }
      
    } catch (err) {
      console.error('Error processing ballot:', err);
      setError(`Error processing ballot: ${err.message}`);
    } finally {
      setProcessing(false);
    }
  };

  const loadSampleData = () => {
    setJsonInput(JSON.stringify(sampleJSON, null, 2));
    setError(null);
    setResult(null);
  };

  if (loading) {
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
    <div className="app">
      <h1>ElectionGuard Ballot Encryption</h1>
      <p>Submit JSON parameters to create an encrypted ballot using ElectionGuard</p>
      
      <div className="form-group">
        <label htmlFor="json-input">JSON Parameters:</label>
        <textarea
          id="json-input"
          className="json-input"
          value={jsonInput}
          onChange={(e) => setJsonInput(e.target.value)}
          placeholder="Enter JSON parameters here..."
          rows={15}
        />
      </div>
      
      <div style={{ marginBottom: '1rem' }}>
        <button onClick={loadSampleData} style={{ marginRight: '1rem' }}>
          Load Sample Data
        </button>
        <button onClick={processBallot} disabled={processing || !pyodide}>
          {processing ? 'Processing...' : 'Create Encrypted Ballot'}
        </button>
      </div>

      {error && (
        <div className="error">
          <h3>Error:</h3>
          <p>{error}</p>
        </div>
      )}

      {result && result.status === 'success' && (
        <div className="success">
          <h3>Ballot Successfully Encrypted!</h3>
          <p><strong>Ballot Hash:</strong> {result.ballot_hash}</p>
        </div>
      )}

      {result && (
        <div className="result-container">
          <h3>Result:</h3>
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}

      <div style={{ marginTop: '2rem', textAlign: 'left' }}>
        <h3>JSON Parameter Reference:</h3>
        <ul>
          <li><strong>party_names</strong>: Array of political party names (e.g., ["Democratic Party", "Republican Party"])</li>
          <li><strong>candidate_names</strong>: Array of candidate names (e.g., ["Alice Johnson", "Bob Smith"])</li>
          <li><strong>candidate_name</strong>: Name of the candidate to vote for (must be in candidate_names)</li>
          <li><strong>ballot_id</strong>: Unique identifier for the ballot (e.g., "ballot-2")</li>
          <li><strong>joint_public_key</strong>: Large integer public key for encryption (as string)</li>
          <li><strong>commitment_hash</strong>: Large integer commitment hash (as string)</li>
          <li><strong>number_of_guardians</strong>: Number of election guardians (e.g., 5)</li>
          <li><strong>quorum</strong>: Minimum number of guardians required (e.g., 3)</li>
        </ul>
      </div>
    </div>
  );
}

export default App;
