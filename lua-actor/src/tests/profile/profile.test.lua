require("setup")

local DFSMUtils = require("utils.dfsm_utils")
local json = require("json")
-- this imports the DFSM processor code
local DFSM = require("dfsm")
-- Import test utilities
local TestUtils = require("test-utils")
local crypto = require(".crypto.init")
local base64 = require(".base64")

-- Test counter for tracking results
local testCounter = { count = 0 }

-- Helper function to run test suite with given configuration
local function runTestSuite(params)
    local inputDir = params.inputDir
    local expectVc = params.expectVc
    local loadInput = params.loadInput

    -- Load agreement document and input files
    local agreementDoc = TestUtils.loadInputDoc(inputDir .. "/profile-agreement" .. (expectVc and ".wrapped" or "") .. ".json")
    
    -- Load all test inputs
    local inputs = {}
    local inputFiles = {
        profile_activation = "input-profile-activation",
        profile_update = "input-profile-update",
        profile_update_2 = "input-profile-update-2",
        profile_update_partial = "input-profile-update-partial",
        profile_deactivation = "input-profile-deactivation",
        profile_reactivation = "input-profile-reactivation"
    }
    
    for key, file in pairs(inputFiles) do
        local path = inputDir .. "/" .. file .. (expectVc and ".wrapped" or "") .. ".json"
        inputs[key] = loadInput(path)
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
    "userEthAddress": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
    "isActive": false
}
]]))
    end

    print(DFSMUtils.formatFSMSummary(dfsm))
    print(DFSMUtils.renderDFSMState(dfsm))

    -- Helper function to format test input
    local function formatTestInput(input, inputId, type, values)
        if expectVc then
            return input
        else
            return string.format([[{
                "type": "VerifiedCredentialEIP712",
                "issuer": "%s",
                "credentialSubject": {
                    "inputId": "%s",
                    "type": "%s",
                    "documentHash": "%s",
                    "values": %s
                }
            }]], 
            "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
            inputId,
            type,
            agreementHash,
            json.encode(values))
        end
    end

    -- Happy Path Test: Profile Lifecycle
    print("\n=== Happy Path: Complete Profile Lifecycle ===")

    -- 1. Profile activation (INACTIVE -> ACTIVE)
    TestUtils.runTest(
        "Profile Activation",
        dfsm,
        formatTestInput(inputs["profile_activation"], "profileActivation", "profileActivation", inputs["profile_activation"].values),
        true,
        nil,
        "ACTIVE",
        DFSMUtils,
        testCounter,
        expectVc
    )

    -- 2. Profile update - complete update (ACTIVE -> ACTIVE)
    TestUtils.runTest(
        "Profile Update - Complete",
        dfsm,
        formatTestInput(inputs["profile_update"], "profileUpdate", "profileUpdate", inputs["profile_update"].values),
        true,
        nil,
        "ACTIVE",
        DFSMUtils,
        testCounter,
        expectVc
    )

    -- 3. Profile update - partial update (ACTIVE -> ACTIVE) - DISABLED FOR NOW
    -- TestUtils.runTest(
    --     "Profile Update - Partial",
    --     dfsm,
    --     formatTestInput(inputs["profile_update_partial"], "profileUpdate", "profileUpdate", inputs["profile_update_partial"].values),
    --     true,
    --     nil,
    --     "ACTIVE",
    --     DFSMUtils,
    --     testCounter,
    --     expectVc
    -- )

    -- 4. Another profile update with different values (ACTIVE -> ACTIVE)
    TestUtils.runTest(
        "Profile Update - Alternative Values",
        dfsm,
        formatTestInput(inputs["profile_update_2"], "profileUpdate", "profileUpdate", inputs["profile_update_2"].values),
        true,
        nil,
        "ACTIVE",
        DFSMUtils,
        testCounter,
        expectVc
    )

    -- 5. Profile deactivation (ACTIVE -> INACTIVE)
    TestUtils.runTest(
        "Profile Deactivation",
        dfsm,
        formatTestInput(inputs["profile_deactivation"], "profileDeactivation", "profileDeactivation", inputs["profile_deactivation"].values),
        true,
        nil,
        "INACTIVE",
        DFSMUtils,
        testCounter,
        expectVc
    )

    -- 6. Profile reactivation (INACTIVE -> ACTIVE)
    TestUtils.runTest(
        "Profile Reactivation",
        dfsm,
        formatTestInput(inputs["profile_reactivation"], "profileActivation", "profileActivation", inputs["profile_reactivation"].values),
        true,
        nil,
        "ACTIVE",
        DFSMUtils,
        testCounter,
        expectVc
    )

    print("=== Happy Path Complete ===\n")
end

-- Run unwrapped test suite only (wrapped tests disabled for now)
print("\n=== Running Profile Agreement Unwrapped Test Suite ===")
runTestSuite({
    inputDir = "./unwrapped",
    expectVc = false,
    loadInput = function(path) return json.decode(TestUtils.loadInputDoc(path)) end
})

-- Print final test summary
print("\n---------------------------------------------")
print("✅ ALL PROFILE TESTS PASSED: " .. testCounter.count .. " tests completed successfully!")
print("No tests failed (execution would have stopped at first failure)")
print("---------------------------------------------") 