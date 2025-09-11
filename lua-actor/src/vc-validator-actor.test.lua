-- Test file for VC Validator Actor
require("setup")

local TestUtils = require("test-utils")
local vc_validator_actor = require("vc-validator-actor")

local Handlers = vc_validator_actor.Handlers

local agreementDoc = TestUtils.loadInputDoc("./tests/mou/wrapped/mou.wrapped.json")

-- Test cases
print("=== VC Validator Actor Tests ===")

-- Test 1: ValidateVC with a valid VC
print("\n1. Testing ValidateVC...")
Handlers.evaluate({
  Tags = { Action = 'ValidateVC' },
  Data = agreementDoc,
  reply = function (response)
    local success = response.Data.success
    print(TestUtils.formatResult(success) .. " ValidateVC message processing")
    assert(success == true)
  end
  },
  { envKey = "envValue" })

  -- Test 2: ValidateVC with a invalid VC
print("\n1. Testing ValidateVC...")
Handlers.evaluate({
  Tags = { Action = 'ValidateVC' },
  Data = [[
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
    "proofValue": "0xe6f0c848788f3886f2179c7d045f68103ff1d466a8c29d9dec5c8d360b48fb8c1610e522f85b435d58db2d70b2217b76440e9ea71ea738aae26e7a661aa9bc9f1d",
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
]],
  reply = function (response)
    local success = response.Data.success
    print(TestUtils.formatResult(success) .. " ValidateVC message processing with invalid VC")
    assert(success == false)
  end
  },
  { envKey = "envValue" })

print("\n=== Tests completed ===")
