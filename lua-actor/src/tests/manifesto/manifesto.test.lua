require("setup")

local DFSMUtils = require("utils.dfsm_utils")
local json = require("json")
-- this imports the DFSM processor code
local DFSM = require("dfsm")
-- Import test utilities
local TestUtils = require("test-utils")
local crypto = require(".crypto.init")

-- Test counter for tracking results
local testCounter = { count = 0 }

-- Helper function to run test suite with given configuration
local function runTestSuite(params)
    local inputDir = params.inputDir
    local expectVc = params.expectVc
    local loadInput = params.loadInput

    -- Load agreement document and input files
    local agreementDoc = TestUtils.loadInputDoc(inputDir .. "/manifesto" .. (expectVc and ".wrapped" or "") .. ".json")
    
    -- Load signature inputs
    local aliceSignature = loadInput(inputDir .. "/input-alice-signature" .. (expectVc and ".wrapped" or "") .. ".json")
    local bobSignature = loadInput(inputDir .. "/input-bob-signature" .. (expectVc and ".wrapped" or "") .. ".json")
    
    -- Load controller inputs (only for wrapped tests)
    local activateInput, deactivateInput
    if expectVc then
        activateInput = loadInput(inputDir .. "/input-activate.wrapped.json")
        deactivateInput = loadInput(inputDir .. "/input-deactivate.wrapped.json")
    end

    -- Extract agreement hash
    local agreementHash
    if expectVc then
        local decodedAgreement = json.decode(agreementDoc)
        local agreementBase64 = decodedAgreement.credentialSubject.agreement
        agreementHash = crypto.digest.keccak256(agreementBase64).asHex()
    else
        agreementHash = crypto.digest.keccak256(agreementDoc).asHex()
    end

    -- Initialize DFSM
    local dfsm
    if expectVc then
        dfsm = DFSM.new(agreementDoc, expectVc)
    else
        dfsm = DFSM.new(agreementDoc, expectVc, json.decode([[
{
    "controller": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4"
}
]]))
    end

    print(DFSMUtils.formatFSMSummary(dfsm))
    print(DFSMUtils.renderDFSMState(dfsm))

    -- Helper function to format test input for both wrapped and unwrapped tests
    local function formatTestInput(input, inputId, issuerAddress, values)
        if expectVc then
            -- For wrapped tests, return the input as-is
            return input
        else
            -- For unwrapped tests, format as DID credential
            return string.format([[{
                "type": "VerifiedCredentialEIP712",
                "issuer": {
                    "id": "did:pkh:eip155:1:%s"
                },
                "credentialSubject": {
                    "inputId": "%s",
                    "type": "signedFields",
                    "documentHash": "%s",
                    "values": %s
                }
            }]], 
            issuerAddress,
            inputId,
            agreementHash,
            json.encode(values))
        end
    end

    -- Test 1: Verify initial state is ACTIVE
    local currentStateId = dfsm.currentState and dfsm.currentState.id or "nil"
    if currentStateId ~= "ACTIVE" then
        error("Expected initial state to be ACTIVE, but got: " .. tostring(currentStateId))
    end
    print("✅ Initial state is ACTIVE as expected")

    -- Test 2: Deactivate manifesto (ACTIVE -> INACTIVE)
    TestUtils.runTest(
        "Deactivate manifesto", 
        dfsm, 
        formatTestInput(deactivateInput, "deactivate", "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4", { activation = "DEACTIVATE" }),
        true,  -- expect success
        nil,
        "INACTIVE",
        DFSMUtils,
        testCounter,
        expectVc
    )

    -- Test 3: Try to deactivate again - should fail as already inactive
    TestUtils.runTest(
        "Try to deactivate when already inactive", 
        dfsm, 
        formatTestInput(deactivateInput, "deactivate", "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4", { activation = "DEACTIVATE" }),
        false,  -- expect failure
        "No valid transition",
        "INACTIVE",  -- state should not change
        DFSMUtils,
        testCounter,
        expectVc
    )

    -- Test 4: Reactivate manifesto (INACTIVE -> ACTIVE)
    TestUtils.runTest(
        "Reactivate manifesto", 
        dfsm, 
        formatTestInput(activateInput, "activate", "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4", { activation = "ACTIVATE" }),
        true,  -- expect success
        nil,
        "ACTIVE",
        DFSMUtils,
        testCounter,
        expectVc
    )

    -- Test 5: Alice signs the manifesto (ACTIVE -> ACTIVE)
    TestUtils.runTest(
        "Alice signs the manifesto", 
        dfsm, 
        formatTestInput(aliceSignature, "signManifesto", 
            expectVc and nil or (type(aliceSignature) == "table" and aliceSignature.values.signerAddress or "0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db"), 
            expectVc and nil or (type(aliceSignature) == "table" and aliceSignature.values or { signerName = "Alice Johnson", signerAddress = "0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db" })),
        true,  -- expect success
        nil,
        "ACTIVE",  -- state remains ACTIVE
        DFSMUtils,
        testCounter,
        expectVc
    )

    -- Test 6: Bob signs the manifesto (ACTIVE -> ACTIVE)
    TestUtils.runTest(
        "Bob signs the manifesto", 
        dfsm, 
        formatTestInput(bobSignature, "signManifesto", 
            expectVc and nil or (type(bobSignature) == "table" and bobSignature.values.signerAddress or "0xBe32388C134a952cdBCc5673E93d46FfD8b85065"), 
            expectVc and nil or (type(bobSignature) == "table" and bobSignature.values or { signerName = "Bob Smith", signerAddress = "0xBe32388C134a952cdBCc5673E93d46FfD8b85065" })),
        true,  -- expect success
        nil,
        "ACTIVE",  -- state remains ACTIVE
        DFSMUtils,
        testCounter,
        expectVc
    )

    -- Test 7: Invalid input ID – should fail with unknown input error
    TestUtils.runTest(
        "Invalid input ID", 
        dfsm, 
        string.format([[{
            "credentialSubject": {
                "inputId": "invalidInput",
                "documentHash": "%s"
            },
            "someValue": true
        }]], agreementHash),
        false,  -- expect failure
        "Unknown input",
        "ACTIVE",  -- state should not change
        DFSMUtils,
        testCounter,
        expectVc
    )

    -- Test 8: Invalid issuer (not controller) - should fail (only for unwrapped tests)
    if not expectVc then
        TestUtils.runTest(
            "Invalid issuer (not controller)", 
            dfsm, 
            formatTestInput(nil, "deactivate", "0x1234567890123456789012345678901234567890", { activation = "DEACTIVATE" }),
            false,  -- expect failure
            "Issuer mismatch",
            "ACTIVE",  -- state should not change
            DFSMUtils,
            testCounter,
            expectVc
        )
    else
        -- For wrapped tests, issuer validation is handled by cryptographic verification
        print("⏭️  Skipping invalid issuer test for wrapped mode (handled by crypto verification)")
        testCounter.count = testCounter.count + 1
    end
end

-- Run unwrapped test suite
print("\n=== Running Unwrapped Test Suite ===")
runTestSuite({
    inputDir = "./unwrapped",
    expectVc = false,
    loadInput = function(path) return json.decode(TestUtils.loadInputDoc(path)) end
})

-- Run wrapped test suite
print("\n=== Running Wrapped Test Suite ===")
runTestSuite({
    inputDir = "./wrapped",
    expectVc = true,
    loadInput = function(path) return TestUtils.loadInputDoc(path) end
})

-- Print final test summary
print("\n---------------------------------------------")
print("✅ ALL TESTS PASSED: " .. testCounter.count .. " tests completed successfully!")
print("No tests failed (execution would have stopped at first failure)")
print("---------------------------------------------") 