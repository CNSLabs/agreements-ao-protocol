require("setup")

local TestUtils = require("test-utils")
local json = require("json")

local apoc = require("manifesto-actor-bundled")
local Handlers = apoc.Handlers
local resetState = apoc.resetState
-- Reset the state before each test to make sure we start fresh
resetState()

-- Load all test input files
local agreementDoc = TestUtils.loadInputDoc("./tests/manifesto/wrapped/manifesto.wrapped.json")
local inputAlice = TestUtils.loadInputDoc("./tests/manifesto/wrapped/input-alice-signature.wrapped.json")
local inputBob = TestUtils.loadInputDoc("./tests/manifesto/wrapped/input-bob-signature.wrapped.json")
local inputActivate = TestUtils.loadInputDoc("./tests/manifesto/wrapped/input-activate.wrapped.json")
local inputDeactivate = TestUtils.loadInputDoc("./tests/manifesto/wrapped/input-deactivate.wrapped.json")

-- Initialize the agreement
local response = Handlers.evaluate({
    Tags = { Action = 'Init' },
    Data = agreementDoc,
    reply = function (response)
      local success = response.Data.success
      print(TestUtils.formatResult(success) .. " Init message processing")
      assert(success == true)
    end
    },
    { envKey = "envValue" }
)

-- Test GetDocument after initialization
response = Handlers.evaluate({
    Tags = { Action = 'GetDocument' },
    Data = json.encode({}),
    reply = function (response)
      local document = response.Data.Document
      local documentHash = response.Data.DocumentHash
      
      assert(document == agreementDoc)
      assert(documentHash == "3f00124f35e74f2eeb60d9f0ed6e695f5589f3351ce822dbb3e40720efc2bd23")
    end
    },
    { envKey = "envValue" }
)

-- Step 1: Alice signature
response = Handlers.evaluate({
    Tags = { Action = 'ProcessInput' },
    Data = json.encode({
        inputValue = json.decode(inputAlice)
    }),
    reply = function (response)
      local success = response.Data.success
      print(TestUtils.formatResult(success) .. " Alice signature processing")
      assert(success == true)
    end
    },
    { envKey = "envValue" }
)

-- Step 2: Bob signature
response = Handlers.evaluate({
    Tags = { Action = 'ProcessInput' },
    Data = json.encode({
        inputValue = json.decode(inputBob)
    }),
    reply = function (response)
      local success = response.Data.success
      print(TestUtils.formatResult(success) .. " Bob signature processing")
      assert(success == true)
    end
    },
    { envKey = "envValue" }
)

-- Step 3: Test duplicate signature rejection
response = Handlers.evaluate({
    Tags = { Action = 'ProcessInput' },
    Data = json.encode({
        inputValue = json.decode(inputAlice)
    }),
    reply = function (response)
      local success = response.Data.success
      print(TestUtils.formatResult(not success) .. " Alice duplicate signature processing")
      assert(success == false)
    end
    },
    { envKey = "envValue" }
)

-- Step 4: Deactivate manifesto
response = Handlers.evaluate({
    Tags = { Action = 'ProcessInput' },
    Data = json.encode({
        inputValue = json.decode(inputDeactivate)
    }),
    reply = function (response)
      local success = response.Data.success
      print(TestUtils.formatResult(success) .. " Deactivate manifesto processing")
      assert(success == true)
    end
    },
    { envKey = "envValue" }
)

-- Step 5: Test signing when inactive
local inactiveSignInput = {
  credentialSubject = {
    inputId = "signManifesto",
    values = {
      signerName = "Charlie Brown",
      signerAddress = "0x1234567890123456789012345678901234567890"
    }
  }
}
response = Handlers.evaluate({
    Tags = { Action = 'ProcessInput' },
    Data = json.encode({
        inputValue = inactiveSignInput
    }),
    reply = function (response)
      local success = response.Data.success
      print(TestUtils.formatResult(not success) .. " Sign when inactive processing")
      assert(success == false)
    end
    },
    { envKey = "envValue" }
)

-- Step 6: Reactivate manifesto
response = Handlers.evaluate({
    Tags = { Action = 'ProcessInput' },
    Data = json.encode({
        inputValue = json.decode(inputActivate)
    }),
    reply = function (response)
      local success = response.Data.success
      print(TestUtils.formatResult(success) .. " Reactivate manifesto processing")
      assert(success == true)
    end
    },
    { envKey = "envValue" }
)

-- Final state check with manifesto-specific data
response = Handlers.evaluate({
    Tags = { Action = 'GetState' },
    Data = json.encode({}),
    reply = function (response)
      local state = response.Data.State
      local isComplete = response.Data.IsComplete
      local signerCount = response.Data.SignerCount
      local signers = response.Data.Signers
      
      -- Check basic state
      assert(isComplete == false, "Manifesto should not be complete - it can continue accepting signatures")
      assert(state.id == "ACTIVE")
      
      -- Check manifesto-specific data
      assert(signerCount == 2, "Expected 2 signers, got " .. tostring(signerCount))
      assert(signers ~= nil, "Signers data should be present")
      
      -- Verify Alice and Bob are in signers
      local aliceFound = false
      local bobFound = false
      for address, signerData in pairs(signers) do
        if string.lower(signerData.address) == "0x67fd5a5ec681b1208308813a2b3a0dd431be7278" then
          aliceFound = true
        elseif string.lower(signerData.address) == "0xbe32388c134a952cdbcc5673e93d46ffd8b85065" then
          bobFound = true
        end
      end
      
      assert(aliceFound, "Alice should be in signers")
      assert(bobFound, "Bob should be in signers")
      
      print(TestUtils.formatResult(true) .. " Final state check with manifesto data")
    end
    },
    { envKey = "envValue" }
)

print("\n---------------------------------------------")
print("✅ Manifesto actor test completed successfully!")
print("---------------------------------------------") 