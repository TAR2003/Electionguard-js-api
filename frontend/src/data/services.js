// Service configuration mapping services to their routes and sample data
export const SERVICES = {
  createEncryptedBallot: {
    name: 'Create Encrypted Ballot',
    shortName: 'Ballot',
    description: 'Create and encrypt a ballot for a specific candidate',
    route: '/create-encrypted-ballot',
    sampleRequest: {
      "party_names": ["Democratic Party", "Republican Party"],
      "candidate_names": ["Alice Johnson", "Bob Smith"],
      "candidate_name": "Alice Johnson",
      "ballot_id": "ballot-2",
      "joint_public_key": "192092755156231671093223778782038695065101522019070175742120001623003267241513757136227863328925910512185841027721697476877549669819431771876592926885052250651672148783368221125549887407084348952231724782364002619614618897369477866471373019039735621390113850105102922212780383631956146377435362595683760875192854590491326598832286888990264264620700364490868486340627499200032922433224175496175887347330409292980437734702642297568062162985068779044666783812358642542859634656068522974300239658153095867913052738128071717368595798314912028334032058564535504771808088137250357855228869309530531240718087076203668553298166523018349788850458853486241800439402387351215799802649275040421956260197330938863809622252568808707955579945500792834586235661908696103943701082379609127781517490835290764835651368135473832396182501490666192312148961526046769270123653279627095276057606514903543526569083228416152395697754329083851400111040417283946287651866590271816627399515875325232910401818298356830563577592225577492879443861313088892592923083407524485369082164220965239246966078405352956257667965562368457043599659039052977657605755900669108673833505421366562480114041533915928368611215085905470214350327727101679130617594875815609554919785397",
      "commitment_hash": "98906773777139738089215984685590350107307121961639735817877463064584850693496",
      "number_of_guardians": 5,
      "quorum": 3
    }
  },
  setupGuardians: {
    name: 'Setup Guardians',
    shortName: 'Setup',
    description: 'Set up election guardians for the key ceremony',
    route: '/setup-guardians',
    sampleRequest: {
      "number_of_guardians": 5,
      "quorum": 3,
      "party_names": ["Democratic Party", "Republican Party"],
      "candidate_names": ["Alice Johnson", "Bob Smith"]
    }
  },
  createEncryptedTally: {
    name: 'Create Encrypted Tally',
    shortName: 'Tally',
    description: 'Create an encrypted tally from multiple ballots',
    route: '/create-encrypted-tally',
    sampleRequest: {
      "encrypted_ballots": [
        {
          "object_id": "ballot-1",
          "contests": [
            {
              "object_id": "contest-1",
              "ballot_selections": [
                {
                  "object_id": "Alice Johnson",
                  "ciphertext": {"pad": "12345", "data": "67890"}
                },
                {
                  "object_id": "Bob Smith", 
                  "ciphertext": {"pad": "54321", "data": "09876"}
                }
              ]
            }
          ]
        }
      ]
    }
  },
  combineDecryptionShares: {
    name: 'Combine Decryption Shares',
    shortName: 'Combine',
    description: 'Combine decryption shares from multiple guardians',
    route: '/combine-decryption-shares',
    sampleRequest: {
      "encrypted_tally": {
        "object_id": "election-tally",
        "contests": {
          "contest-1": {
            "object_id": "contest-1",
            "selections": {
              "Alice Johnson": {
                "object_id": "Alice Johnson",
                "ciphertext": {"pad": "12345", "data": "67890"}
              },
              "Bob Smith": {
                "object_id": "Bob Smith",
                "ciphertext": {"pad": "54321", "data": "09876"}
              }
            }
          }
        }
      },
      "decryption_shares": {
        "guardian-1": {
          "contest-1": {
            "Alice Johnson": {"partial_decryption": "6172"},
            "Bob Smith": {"partial_decryption": "27160"}
          }
        },
        "guardian-2": {
          "contest-1": {
            "Alice Johnson": {"partial_decryption": "6173"},
            "Bob Smith": {"partial_decryption": "27161"}
          }
        }
      }
    }
  },
  compensatedDecryption: {
    name: 'Create Compensated Decryption',
    shortName: 'Compensated',
    description: 'Create compensated decryption shares when guardians are missing',
    route: '/compensated-decryption',
    sampleRequest: {
      "encrypted_tally": {
        "object_id": "election-tally",
        "contests": {
          "contest-1": {
            "object_id": "contest-1",
            "selections": {
              "Alice Johnson": {
                "object_id": "Alice Johnson",
                "ciphertext": {"pad": "12345", "data": "67890"}
              }
            }
          }
        }
      },
      "available_guardians": ["guardian-1", "guardian-2", "guardian-3"],
      "missing_guardians": ["guardian-4", "guardian-5"]
    }
  },
  partialDecryption: {
    name: 'Partial Decryption',
    shortName: 'Partial',
    description: 'Create partial decryption shares from guardians',
    route: '/partial-decryption',
    sampleRequest: {
      "encrypted_tally": {
        "object_id": "election-tally",
        "contests": {
          "contest-1": {
            "object_id": "contest-1",
            "selections": {
              "Alice Johnson": {
                "object_id": "Alice Johnson",
                "ciphertext": {"pad": "12345", "data": "67890"}
              },
              "Bob Smith": {
                "object_id": "Bob Smith",
                "ciphertext": {"pad": "54321", "data": "09876"}
              }
            }
          }
        }
      },
      "guardian_id": "guardian-1"
    }
  }
};

export const SERVICE_KEYS = Object.keys(SERVICES);
export const SERVICE_NAMES = SERVICE_KEYS.map(key => SERVICES[key].name);
