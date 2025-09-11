require("setup")

local VcValidator = require("vc-validator")

-- Test 1: get_authority did:pkh format
local did_pkh = "did:pkh:eip155:1:0xB49e45Affd4963374e72f850B6Cae84939e58F78"
local result1 = VcValidator.get_authority(did_pkh)
assert(result1 == "0xb49e45affd4963374e72f850b6cae84939e58f78", "Failed to get authority for did:pkh format")

-- Test 2: get_authority for did:ethr format
local did_ethr = "did:ethr:0xB49e45Affd4963374e72f850B6Cae84939e58F78"
local result2 = VcValidator.get_authority(did_ethr)
assert(result2 == "0xb49e45affd4963374e72f850b6cae84939e58f78", "Failed to get authority for did:ethr format")

-- Test 3: get_authority for invalid format
local invalid_did = "did:invalid:0xB49e45Affd4963374e72f850B6Cae84939e58F78"
local success, error_msg = pcall(VcValidator.get_authority, invalid_did)
assert(not success, "Expected error for invalid format")

-- validating a VC that contains an array of primitive values
local success, vcJson, ownerAddress = VcValidator.validate([[
{
  "issuer": {
    "id": "did:pkh:eip155:1:0xB49e45Affd4963374e72f850B6Cae84939e58F78"
  },
  "credentialSubject": {
    "id": "partyAData",
    "type": "signedFields",
    "fields": [
      "foo",
      "bar"
    ]
  },
  "type": [
    "VerifiableCredential",
    "AgreementCredential"
  ],
  "issuanceDate": "2025-04-10T21:50:08.720Z",
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "proof": {
    "verificationMethod": "did:pkh:eip155:1:0xB49e45Affd4963374e72f850B6Cae84939e58F78#blockchainAccountId",
    "created": "2025-04-10T21:50:08.720Z",
    "proofPurpose": "assertionMethod",
    "type": "EthereumEip712Signature2021",
    "proofValue": "0xe6f0c848788f3886f2179c7d045f68103ff1d466a8c29d9dec5c8d360b48fb8c1610e522f85b435d58db2d70b2217b76440e9ea71ea738aae26e7a661aa9bc9f1c",
    "eip712": {
      "domain": {
        "chainId": 1,
        "name": "VerifiableCredential",
        "version": "1"
      },
      "types": {
        "EIP712Domain": [
          {
            "name": "name",
            "type": "string"
          },
          {
            "name": "version",
            "type": "string"
          },
          {
            "name": "chainId",
            "type": "uint256"
          }
        ],
        "CredentialSubject": [
          {
            "name": "fields",
            "type": "string[]"
          },
          {
            "name": "id",
            "type": "string"
          },
          {
            "name": "type",
            "type": "string"
          }
        ],
        "Issuer": [
          {
            "name": "id",
            "type": "string"
          }
        ],
        "Proof": [
          {
            "name": "created",
            "type": "string"
          },
          {
            "name": "proofPurpose",
            "type": "string"
          },
          {
            "name": "type",
            "type": "string"
          },
          {
            "name": "verificationMethod",
            "type": "string"
          }
        ],
        "VerifiableCredential": [
          {
            "name": "@context",
            "type": "string[]"
          },
          {
            "name": "credentialSubject",
            "type": "CredentialSubject"
          },
          {
            "name": "issuanceDate",
            "type": "string"
          },
          {
            "name": "issuer",
            "type": "Issuer"
          },
          {
            "name": "proof",
            "type": "Proof"
          },
          {
            "name": "type",
            "type": "string[]"
          }
        ]
      },
      "primaryType": "VerifiableCredential"
    }
  }
}
]])
assert(success, "Failed to validate VC")
assert(ownerAddress == "0xb49e45affd4963374e72f850b6cae84939e58f78")

-- validating a VC that contains an array of structs (Fields[])
success, vcJson, ownerAddress = VcValidator.validate([[
{
  "issuer": {
    "id": "did:pkh:eip155:1:0xB49e45Affd4963374e72f850B6Cae84939e58F78"
  },
  "credentialSubject": {
    "id": "partyAData",
    "type": "signedFields",
    "fields": [
      {
        "id": "partyAName",
        "value": "Damian"
      },
      {
        "id": "partyAEthAddress",
        "value": "0x2a6fFb5341F8C1cE123343162E3351F1B6286C43"
      }
    ]
  },
  "type": [
    "VerifiableCredential",
    "AgreementCredential"
  ],
  "issuanceDate": "2025-04-10T14:10:18.040Z",
  "@context": [
    "https://www.w3.org/2018/credentials/v1"
  ],
  "proof": {
    "verificationMethod": "did:pkh:eip155:1:0xB49e45Affd4963374e72f850B6Cae84939e58F78#blockchainAccountId",
    "created": "2025-04-10T14:10:18.040Z",
    "proofPurpose": "assertionMethod",
    "type": "EthereumEip712Signature2021",
    "proofValue": "0x005ba32358d2b208d6515bd1d91cb5dff4270f9d2802a5a40c670960e60d7fbe6d224796b553efd2e6dfd38136a1049fae069d2050d5421aa65cbfd56c19bcec1c",
    "eip712": {
      "domain": {
        "chainId": 1,
        "name": "VerifiableCredential",
        "version": "1"
      },
      "types": {
        "EIP712Domain": [
          {
            "name": "name",
            "type": "string"
          },
          {
            "name": "version",
            "type": "string"
          },
          {
            "name": "chainId",
            "type": "uint256"
          }
        ],
        "CredentialSubject": [
          {
            "name": "fields",
            "type": "Fields[]"
          },
          {
            "name": "id",
            "type": "string"
          },
          {
            "name": "type",
            "type": "string"
          }
        ],
        "Fields": [
          {
            "name": "id",
            "type": "string"
          },
          {
            "name": "value",
            "type": "string"
          }
        ],
        "Issuer": [
          {
            "name": "id",
            "type": "string"
          }
        ],
        "Proof": [
          {
            "name": "created",
            "type": "string"
          },
          {
            "name": "proofPurpose",
            "type": "string"
          },
          {
            "name": "type",
            "type": "string"
          },
          {
            "name": "verificationMethod",
            "type": "string"
          }
        ],
        "VerifiableCredential": [
          {
            "name": "@context",
            "type": "string[]"
          },
          {
            "name": "credentialSubject",
            "type": "CredentialSubject"
          },
          {
            "name": "issuanceDate",
            "type": "string"
          },
          {
            "name": "issuer",
            "type": "Issuer"
          },
          {
            "name": "proof",
            "type": "Proof"
          },
          {
            "name": "type",
            "type": "string[]"
          }
        ]
      },
      "primaryType": "VerifiableCredential"
    }
  }
}
]])
assert(success, "Failed to validate VC")
assert(ownerAddress == "0xb49e45affd4963374e72f850b6cae84939e58f78")