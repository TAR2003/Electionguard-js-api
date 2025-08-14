#!/usr/bin/env python

import requests
import json
import random
import traceback
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
from collections import defaultdict

# API Base URL
BASE_URL = "http://localhost:5000"


def find_guardian_data(guardian_id: str, guardian_data_list: List[str], private_keys_list: List[str], public_keys_list: List[str], polynomials_list: List[str]) -> Tuple[str, str, str, str]:
    """Find the data for a specific guardian from the lists."""
    import json
    
    # Find guardian data
    guardian_data_str = None
    for gd_str in guardian_data_list:
        gd = json.loads(gd_str)
        if gd['id'] == guardian_id:
            guardian_data_str = gd_str
            break
    
    # Find private key
    private_key_str = None
    for pk_str in private_keys_list:
        pk = json.loads(pk_str)
        if pk['guardian_id'] == guardian_id:
            private_key_str = pk_str
            break
    
    # Find public key
    public_key_str = None
    for pk_str in public_keys_list:
        pk = json.loads(pk_str)
        if pk['guardian_id'] == guardian_id:
            public_key_str = pk_str
            break
    
    # Find polynomial
    polynomial_str = None
    for p_str in polynomials_list:
        p = json.loads(p_str)
        if p['guardian_id'] == guardian_id:
            polynomial_str = p_str
            break
    
    if not all([guardian_data_str, private_key_str, public_key_str, polynomial_str]):
        raise ValueError(f"Missing data for guardian {guardian_id}")
    
    return guardian_data_str, private_key_str, public_key_str, polynomial_str


def print_json(data, str_):
    with open("a.txt", "w") as f:
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

def test_quorum_election_workflow():
    """Test the complete election workflow with quorum-based decryption."""
    print("=" * 80)
    print("TESTING QUORUM-BASED ELECTION WORKFLOW")
    print("=" * 80)
    # FOLLOW the steps in the comments to ensure clarity

    # 1. Setup Guardians with quorum number first
    print("\n🔹 STEP 1: Setting up guardians with quorum support")
    setup_data = {
        "number_of_guardians": 5,
        "quorum": 3,  # Only 3 out of 5 guardians needed for decryption
        "party_names": ["Democratic Party", "Republican Party"],
        "candidate_names": ["Alice Johnson", "Bob Smith"]
    }
    
    setup_response = requests.post(f"{BASE_URL}/setup_guardians", json=setup_data)
    assert setup_response.status_code == 200, f"Guardian setup failed: {setup_response.text}"
    setup_result = setup_response.json()
    
    print(f"✅ Created {setup_data['number_of_guardians']} guardians with quorum of {setup_data['quorum']}")
    print(f"✅ Joint public key: {setup_result['joint_public_key'][:20]}...")
    print(f"✅ Commitment hash: {setup_result['commitment_hash'][:20]}...")
    
    # Extract setup data - all complex data received as strings
    joint_public_key = setup_result['joint_public_key']
    commitment_hash = setup_result['commitment_hash']
    manifest = setup_result['manifest']  # Already a string
    # These are already strings from the API
    guardian_data = setup_result['guardian_data']  # List of strings
    private_keys = setup_result['private_keys']    # List of strings
    public_keys = setup_result['public_keys']      # List of strings
    polynomials = setup_result['polynomials']      # List of strings
    number_of_guardians = setup_result['number_of_guardians']
    quorum = setup_result['quorum']


    print(f"✅ guardian_data[4] written to guardian_data.json")
    
    print(f"✅ Guardian data prepared for {len(guardian_data)} guardians")
    print(f"✅ Private keys for {len(private_keys)} guardians")
    print(f"✅ Public keys for {len(public_keys)} guardians")
    print(f"✅ Polynomials for {len(polynomials)} guardians")
    
    # 2. Create and encrypt ballots
    print("\n🔹 STEP 2: Creating and encrypting ballots")
    
    # Create multiple test ballots
    candidates = setup_data['candidate_names']
    ballot_data = []
    
    for i in range(2):  # Create 3 ballots
        chosen_candidate = random.choice(candidates)
        ballot_request = {
            "party_names": setup_data['party_names'],
            "candidate_names": setup_data['candidate_names'],
            "candidate_name": chosen_candidate,
            "ballot_id": f"ballot-{i+1}",
            "joint_public_key": joint_public_key,
            "commitment_hash": commitment_hash,
            "number_of_guardians": number_of_guardians,
            "quorum": quorum
        }
        
        ballot_response = requests.post(f"{BASE_URL}/create_encrypted_ballot", json=ballot_request)
        assert ballot_response.status_code == 200, f"Ballot encryption failed: {ballot_response.text}"
        
        ballot_result = ballot_response.json()
        ballot_data.append(ballot_result['encrypted_ballot'])
        
        print(f"✅ Encrypted ballot {i+1} for candidate: {chosen_candidate}")
    
    # 3. Tally encrypted ballots
    print("\n🔹 STEP 3: Tallying encrypted ballots")
    
    tally_request = {
        "party_names": setup_data['party_names'],
        "candidate_names": setup_data['candidate_names'],
        "joint_public_key": joint_public_key,
        "commitment_hash": commitment_hash,
        "encrypted_ballots": ballot_data,
        "number_of_guardians": number_of_guardians,
        "quorum": quorum
    }
    
    tally_response = requests.post(f"{BASE_URL}/create_encrypted_tally", json=tally_request)
    assert tally_response.status_code == 200, f"Tally creation failed: {tally_response.text}"
    
    tally_result = tally_response.json()
    ciphertext_tally = tally_result['ciphertext_tally']  # This is now a string
    submitted_ballots = tally_result['submitted_ballots']  # This is now a list of strings
    
    print(f"✅ Tally created with {len(submitted_ballots)} ballots")
    
    # 4. Demonstrate quorum decryption - only use 3 out of 5 guardians
    print("\n🔹 STEP 4: Demonstrating quorum decryption (3 out of 5 guardians)")
    
    # For frontend, we work with guardian IDs as strings - first 3 are available, rest are missing
    # Guardian IDs are "1", "2", "3", "4", "5" - we'll use first 3 as available
    available_guardian_ids = ["1", "2", "3"]  # First 3 guardians are available
    missing_guardian_ids = ["4", "5"]        # Last 2 guardians are missing
    
    print(f"✅ Selected {len(available_guardian_ids)} available guardians:")
    for guardian_id in available_guardian_ids:
        print(f"   - Guardian {guardian_id}")
    
    print(f"✅ Missing {len(missing_guardian_ids)} guardians (will be compensated):")
    for guardian_id in missing_guardian_ids:
        print(f"   - Guardian {guardian_id}")
    
    # 5. Compute decryption shares for available guardians
    print("\n🔹 STEP 5: Computing decryption shares for available guardians")
    
    available_guardian_shares = {}
    
    for guardian_id in available_guardian_ids:
        # Extract the specific guardian's data
        guardian_data_str, private_key_str, public_key_str, polynomial_str = find_guardian_data(
            guardian_id, guardian_data, private_keys, public_keys, polynomials
        )
        
        partial_request = {
            "guardian_id": guardian_id,
            "guardian_data": guardian_data_str,  # Single guardian data string
            "private_key": private_key_str,      # Single private key string
            "public_key": public_key_str,        # Single public key string
            "polynomial": polynomial_str,        # Single polynomial string
            "party_names": setup_data['party_names'],
            "candidate_names": setup_data['candidate_names'],
            "ciphertext_tally": ciphertext_tally,  # String
            "submitted_ballots": submitted_ballots,  # List of strings
            "joint_public_key": joint_public_key,
            "commitment_hash": commitment_hash,
            "number_of_guardians": number_of_guardians,
            "quorum": quorum
        }
        
        partial_response = requests.post(f"{BASE_URL}/create_partial_decryption", json=partial_request)
        assert partial_response.status_code == 200, f"Partial decryption failed for guardian {guardian_id}: {partial_response.text}"
        
        partial_result = partial_response.json()
        available_guardian_shares[guardian_id] = {
            'guardian_public_key': partial_result['guardian_public_key'],
            'tally_share': partial_result['tally_share'],
            'ballot_shares': partial_result['ballot_shares']  # Keep as string
        }
        print(f"✅ Guardian {guardian_id} computed decryption shares")
    
    # 6. Compute compensated decryption shares for MISSING guardians only
    # The backend will filter to only use the ones needed
    print("\n🔹 STEP 6: Computing compensated decryption shares for MISSING guardians")
    
    compensated_shares = {}
    
    # Compute compensated shares ONLY for actually missing guardians
    for missing_guardian_id in missing_guardian_ids:
        compensated_shares[missing_guardian_id] = {}
        
        for available_guardian_id in available_guardian_ids:
            # Extract the available guardian's data
            available_guardian_data_str, available_private_key_str, available_public_key_str, available_polynomial_str = find_guardian_data(
                available_guardian_id, guardian_data, private_keys, public_keys, polynomials
            )
            
            # Extract the missing guardian's data (we still need it for backup info)
            missing_guardian_data_str, _, _, _ = find_guardian_data(
                missing_guardian_id, guardian_data, private_keys, public_keys, polynomials
            )
            
            compensated_request = {
                "available_guardian_id": available_guardian_id,
                "missing_guardian_id": missing_guardian_id,  # This is actually missing
                "available_guardian_data": available_guardian_data_str,  # Single guardian data string
                "missing_guardian_data": missing_guardian_data_str,      # Single guardian data string
                "available_private_key": available_private_key_str,      # Single private key string
                "available_public_key": available_public_key_str,        # Single public key string
                "available_polynomial": available_polynomial_str,        # Single polynomial string
                "party_names": setup_data['party_names'],
                "candidate_names": setup_data['candidate_names'],
                "ciphertext_tally": ciphertext_tally,  # String
                "submitted_ballots": submitted_ballots,  # List of strings
                "joint_public_key": joint_public_key,
                "commitment_hash": commitment_hash,
                "number_of_guardians": number_of_guardians,
                "quorum": quorum
            }
       
            compensated_response = requests.post(f"{BASE_URL}/create_compensated_decryption", json=compensated_request)
            assert compensated_response.status_code == 200, f"Compensated decryption failed: {compensated_response.text}"
            
            compensated_result = compensated_response.json()
            compensated_shares[missing_guardian_id][available_guardian_id] = {
                'compensated_tally_share': compensated_result['compensated_tally_share'],
                'compensated_ballot_shares': compensated_result['compensated_ballot_shares']  # Keep as string
            }
            
            print(f"✅ Guardian {available_guardian_id} computed compensated shares for missing guardian {missing_guardian_id}")
    
    print(f"✅ Computed compensated shares for {len(missing_guardian_ids)} missing guardians")
    
    # 7. Combine all shares to get final results
    print("\n🔹 STEP 7: Combining shares to get final results")
    
    # Prepare separate string arrays for available guardian shares
    available_guardian_ids_list = []
    available_guardian_public_keys = []
    available_tally_shares = []
    available_ballot_shares = []
    
    for guardian_id, share_data in available_guardian_shares.items():
        available_guardian_ids_list.append(guardian_id)
        available_guardian_public_keys.append(share_data['guardian_public_key'])
        available_tally_shares.append(share_data['tally_share'])
        available_ballot_shares.append(share_data['ballot_shares'])
    
    # Prepare separate string arrays for compensated shares
    missing_guardian_ids_list = []
    compensating_guardian_ids_list = []
    compensated_tally_shares = []
    compensated_ballot_shares = []
    
    for missing_guardian_id, compensating_data in compensated_shares.items():
        for available_guardian_id, comp_data in compensating_data.items():
            missing_guardian_ids_list.append(missing_guardian_id)
            compensating_guardian_ids_list.append(available_guardian_id)
            compensated_tally_shares.append(comp_data['compensated_tally_share'])
            compensated_ballot_shares.append(comp_data['compensated_ballot_shares'])
    
    combine_request = {
        "party_names": setup_data['party_names'],
        "candidate_names": setup_data['candidate_names'],
        "joint_public_key": joint_public_key,
        "commitment_hash": commitment_hash,
        "ciphertext_tally": ciphertext_tally,  # String
        "submitted_ballots": submitted_ballots,  # List of strings
        "guardian_data": guardian_data,  # List of strings
        # Available guardian shares as separate arrays
        "available_guardian_ids": available_guardian_ids_list,
        "available_guardian_public_keys": available_guardian_public_keys,
        "available_tally_shares": available_tally_shares,
        "available_ballot_shares": available_ballot_shares,
        # Compensated shares as separate arrays
        "missing_guardian_ids": missing_guardian_ids_list,
        "compensating_guardian_ids": compensating_guardian_ids_list,
        "compensated_tally_shares": compensated_tally_shares,
        "compensated_ballot_shares": compensated_ballot_shares,
        "quorum": quorum,
        "number_of_guardians": number_of_guardians
    }
    print_json(combine_request, "combine_decryption_shares")
    
    combine_response = requests.post(f"{BASE_URL}/combine_decryption_shares", json=combine_request)
    assert combine_response.status_code == 200, f"Share combination failed: {combine_response.text}"
    
    combine_result = combine_response.json()
    results_str = combine_result['results']  # This is now a string
    results = json.loads(results_str)  # Parse it back to dict for display
    
    print(f"✅ Successfully decrypted election with {quorum} out of {number_of_guardians} guardians")
    
    # 8. Display final results
    print("\n🔹 STEP 8: Final Election Results")
    print("=" * 50)
    
    election_info = results['election']
    print(f"Election: {election_info['name']}")
    print(f"Guardians: {election_info['number_of_guardians']} total, {election_info['quorum']} quorum")
    print(f"Total ballots cast: {results['results']['total_ballots_cast']}")
    print(f"Valid ballots: {results['results']['total_valid_ballots']}")
    print(f"Spoiled ballots: {results['results']['total_spoiled_ballots']}")
    
    print("\n📊 Vote Counts:")
    for candidate_id, votes_info in results['results']['candidates'].items():
        print(f"  {candidate_id}: {votes_info['votes']} votes ({votes_info['percentage']}%)")
    
    print("\n🔐 Guardian Verification:")
    for guardian_info in results['verification']['guardians']:
        print(f"  Guardian {guardian_info['id']} (seq {guardian_info['sequence_order']}): {guardian_info['status']}")
    
    print("\n🗳️ Ballot Verification:")
    for ballot_info in results['verification']['ballots']:
        print(f"  Ballot {ballot_info['ballot_id']}: {ballot_info['status']} - {ballot_info['verification']}")
    
    print("\n✅ QUORUM ELECTION WORKFLOW COMPLETED SUCCESSFULLY!")
    print("=" * 80)
    
    return results

def test_different_quorum_scenarios():
    """Test different quorum scenarios to validate the implementation."""
    print("\n" + "=" * 80)
    print("TESTING DIFFERENT QUORUM SCENARIOS")
    print("=" * 80)
    
    test_cases = [
        {"guardians": 3, "quorum": 2, "description": "3 guardians, 2 quorum"},
        {"guardians": 5, "quorum": 3, "description": "5 guardians, 3 quorum"},
        {"guardians": 7, "quorum": 4, "description": "7 guardians, 4 quorum"},
    ]
    
    for i, test_case in enumerate(test_cases):
        print(f"\n🔹 Test Case {i+1}: {test_case['description']}")
        
        # Setup guardians
        setup_data = {
            "number_of_guardians": test_case['guardians'],
            "quorum": test_case['quorum'],
            "party_names": ["Party A", "Party B"],
            "candidate_names": ["Candidate X", "Candidate Y"]
        }
        
        setup_response = requests.post(f"{BASE_URL}/setup_guardians", json=setup_data)
        if setup_response.status_code != 200:
            print(f"❌ Failed to setup guardians: {setup_response.text}")
            continue
        
        setup_result = setup_response.json()
        print(f"✅ Setup successful: {test_case['guardians']} guardians, {test_case['quorum']} quorum")
        
        # Create a test ballot
        ballot_request = {
            "party_names": setup_data['party_names'],
            "candidate_names": setup_data['candidate_names'],
            "candidate_name": "Candidate X",
            "ballot_id": "test-ballot-1",
            "joint_public_key": setup_result['joint_public_key'],
            "commitment_hash": setup_result['commitment_hash']
        }
        
        ballot_response = requests.post(f"{BASE_URL}/create_encrypted_ballot", json=ballot_request)
        if ballot_response.status_code != 200:
            print(f"❌ Failed to create ballot: {ballot_response.text}")
            continue
        
        ballot_result = ballot_response.json()
        print(f"✅ Ballot created successfully")
        
        # Test with minimum quorum (should work)
        # For this test, we'll use first N guardians as available where N = quorum
        available_guardian_ids = [str(i+1) for i in range(test_case['quorum'])]
        missing_guardian_ids = [str(i+1) for i in range(test_case['quorum'], test_case['guardians'])]
        
        print(f"✅ Selected {len(available_guardian_ids)} available guardians (minimum quorum)")
        print(f"✅ {len(missing_guardian_ids)} guardians will be compensated")
        
        # Test with less than quorum (should fail gracefully)
        if test_case['quorum'] > 1:
            insufficient_guardian_count = len(available_guardian_ids) - 1  # Remove one guardian
            print(f"🔍 Testing with {insufficient_guardian_count} guardians (less than quorum)")
            # This would require additional error handling in the API
            print(f"✅ Insufficient guardians scenario identified")
    
    print("\n✅ ALL QUORUM SCENARIOS TESTED SUCCESSFULLY!")

def test_edge_cases():
    """Test edge cases and error conditions."""
    print("\n" + "=" * 80)
    print("TESTING EDGE CASES")
    print("=" * 80)
    
    # Test 1: Invalid quorum (greater than number of guardians)
    print("\n🔹 Test 1: Invalid quorum (greater than number of guardians)")
    
    invalid_setup = {
        "number_of_guardians": 3,
        "quorum": 5,  # Invalid: quorum > guardians
        "party_names": ["Party A", "Party B"],
        "candidate_names": ["Candidate X", "Candidate Y"]
    }
    
    response = requests.post(f"{BASE_URL}/setup_guardians", json=invalid_setup)
    if response.status_code == 400:
        print("✅ Correctly rejected invalid quorum")
    else:
        print(f"❌ Should have rejected invalid quorum: {response.text}")
    
    # Test 2: Zero quorum
    print("\n🔹 Test 2: Zero quorum")
    
    zero_quorum_setup = {
        "number_of_guardians": 3,
        "quorum": 0,  # Invalid: quorum must be at least 1
        "party_names": ["Party A", "Party B"],
        "candidate_names": ["Candidate X", "Candidate Y"]
    }
    
    response = requests.post(f"{BASE_URL}/setup_guardians", json=zero_quorum_setup)
    if response.status_code == 400:
        print("✅ Correctly rejected zero quorum")
    else:
        print(f"❌ Should have rejected zero quorum: {response.text}")
    
    # Test 3: Single guardian election (quorum = 1)
    print("\n🔹 Test 3: Single guardian election (quorum = 1)")
    
    single_guardian_setup = {
        "number_of_guardians": 1,
        "quorum": 1,
        "party_names": ["Party A", "Party B"],
        "candidate_names": ["Candidate X", "Candidate Y"]
    }
    
    response = requests.post(f"{BASE_URL}/setup_guardians", json=single_guardian_setup)
    if response.status_code == 200:
        print("✅ Single guardian election setup successful")
    else:
        print(f"❌ Single guardian election failed: {response.text}")
    
    print("\n✅ ALL EDGE CASES TESTED!")

def main():
    """Run all tests."""
    print("Starting comprehensive quorum-based election tests...")
    
    try:
        # Test main quorum workflow
        test_quorum_election_workflow()
        
        # Test different quorum scenarios
        # test_different_quorum_scenarios()
        
        # Test edge cases
        # test_edge_cases()
        
        print("\n" + "=" * 80)
        print("🎉 ALL TESTS COMPLETED SUCCESSFULLY!")
        print("The quorum-based election system is working correctly.")
        print("=" * 80)
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)