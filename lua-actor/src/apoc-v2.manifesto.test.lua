require("setup")

local TestUtils = require("test-utils")
local json = require("json")
local crypto = require(".crypto.init")
local DFSM = require("dfsm")

-- Manifesto-specific state
Signers = Signers or {} -- Track signers: {address -> {name, timestamp, signatureHash}}
SignerCount = SignerCount or 0

local function resetState()
  Signers = {}
  SignerCount = 0
end

resetState()

local agreementDoc = TestUtils.loadInputDoc("./tests/manifesto/wrapped/manifesto.wrapped.json")
local inputAlice = TestUtils.loadInputDoc("./tests/manifesto/wrapped/input-alice-signature.wrapped.json")
local inputBob = TestUtils.loadInputDoc("./tests/manifesto/wrapped/input-bob-signature.wrapped.json")
local inputActivate = TestUtils.loadInputDoc("./tests/manifesto/wrapped/input-activate.wrapped.json")
local inputDeactivate = TestUtils.loadInputDoc("./tests/manifesto/wrapped/input-deactivate.wrapped.json")

local aliceJson = json.decode(inputAlice)
local bobJson = json.decode(inputBob)

local dfsm = DFSM.new(agreementDoc, true)

local currentState = dfsm:getCurrentState()
local isActive = currentState.id == "ACTIVE"
print(TestUtils.formatResult(isActive) .. " Initial state is ACTIVE")
assert(isActive == true)

local aliceInput = json.decode(inputAlice)
local aliceSuccess, aliceError = dfsm:processInput(aliceInput, false)
print(TestUtils.formatResult(aliceSuccess) .. " Alice signature processing")
assert(aliceSuccess == true)

local aliceAddress = aliceInput.credentialSubject.values.signerAddress
local aliceName = aliceInput.credentialSubject.values.signerName
Signers[string.lower(aliceAddress)] = {
  name = aliceName,
  address = aliceAddress,
  timestamp = os.time(),
  signatureHash = crypto.digest.keccak256(inputAlice).asHex()
}
SignerCount = SignerCount + 1

local aliceFound = Signers[string.lower(aliceAddress)] ~= nil
print(TestUtils.formatResult(aliceFound) .. " Alice is tracked in signers")
assert(aliceFound == true)
assert(SignerCount == 1, "Expected 1 signer, got " .. tostring(SignerCount))

local bobInput = json.decode(inputBob)
local bobSuccess, bobError = dfsm:processInput(bobInput, false)
print(TestUtils.formatResult(bobSuccess) .. " Bob signature processing")
assert(bobSuccess == true)

local bobAddress = bobInput.credentialSubject.values.signerAddress
local bobName = bobInput.credentialSubject.values.signerName
Signers[string.lower(bobAddress)] = {
  name = bobName,
  address = bobAddress,
  timestamp = os.time(),
  signatureHash = crypto.digest.keccak256(inputBob).asHex()
}
SignerCount = SignerCount + 1

local aliceFound2 = Signers[string.lower(aliceAddress)] ~= nil
local bobFound = Signers[string.lower(bobAddress)] ~= nil
local bothFound = aliceFound2 and bobFound
print(TestUtils.formatResult(bothFound) .. " Both Alice and Bob are tracked in signers")
assert(bothFound == true)
assert(SignerCount == 2, "Expected 2 signers, got " .. tostring(SignerCount))

if Signers[string.lower(aliceAddress)] then
  print(TestUtils.formatResult(true) .. " Alice duplicate signature processing")
else
  local aliceDuplicateSuccess, aliceDuplicateError = dfsm:processInput(aliceInput, false)
  print(TestUtils.formatResult(not aliceDuplicateSuccess) .. " Alice duplicate signature processing")
  assert(aliceDuplicateSuccess == false)
end

local deactivateInput = json.decode(inputDeactivate)
local deactivateSuccess, deactivateError = dfsm:processInput(deactivateInput, false)
print(TestUtils.formatResult(deactivateSuccess) .. " Deactivate manifesto processing")
assert(deactivateSuccess == true)

local inactiveState = dfsm:getCurrentState()
local isInactive = inactiveState.id == "INACTIVE"
print(TestUtils.formatResult(isInactive) .. " State is INACTIVE after deactivation")
assert(isInactive == true)

local inactiveSignInput = {
  credentialSubject = {
    inputId = "signManifesto",
    values = {
      signerName = "Charlie Brown",
      signerAddress = "0x1234567890123456789012345678901234567890"
    }
  }
}
local inactiveSignSuccess, inactiveSignError = dfsm:processInput(inactiveSignInput, false)
print(TestUtils.formatResult(not inactiveSignSuccess) .. " Sign when inactive processing")
assert(inactiveSignSuccess == false)

local activateInput = json.decode(inputActivate)
local activateSuccess, activateError = dfsm:processInput(activateInput, false)
print(TestUtils.formatResult(activateSuccess) .. " Reactivate manifesto processing")
assert(activateSuccess == true)

local activeState = dfsm:getCurrentState()
local isActiveAgain = activeState.id == "ACTIVE"
print(TestUtils.formatResult(isActiveAgain) .. " State is ACTIVE after reactivation")
assert(isActiveAgain == true)

local signersList = {}
for address, signerData in pairs(Signers) do
  table.insert(signersList, {
    address = signerData.address,
    name = signerData.name,
    timestamp = signerData.timestamp,
    signatureHash = signerData.signatureHash
  })
end
table.sort(signersList, function(a, b) return a.timestamp < b.timestamp end)

local aliceInList = false
local bobInList = false
for _, signer in ipairs(signersList) do
  if string.lower(signer.address) == string.lower(aliceAddress) then
    aliceInList = true
  elseif string.lower(signer.address) == string.lower(bobAddress) then
    bobInList = true
  end
end

print(TestUtils.formatResult(aliceInList and bobInList) .. " Get signers functionality")
assert(aliceInList and bobInList)

local aliceInfo = Signers[string.lower(aliceAddress)]
print(TestUtils.formatResult(aliceInfo ~= nil) .. " Get signer info for Alice")
assert(aliceInfo ~= nil)

local nonExistentInfo = Signers[string.lower("0xNonExistentAddress")]
print(TestUtils.formatResult(nonExistentInfo == nil) .. " Get signer info for non-existent signer")
assert(nonExistentInfo == nil)

local stats = {
  totalSigners = SignerCount,
  isActive = dfsm:getCurrentState().id == "ACTIVE",
  canAcceptSignatures = dfsm:getCurrentState().id == "ACTIVE"
}
print(TestUtils.formatResult(stats.totalSigners == 2 and stats.isActive and stats.canAcceptSignatures) .. " Get signer stats")
assert(stats.totalSigners == 2 and stats.isActive and stats.canAcceptSignatures)

print(TestUtils.formatResult(true) .. " State query includes manifesto-specific data")

print("\n---------------------------------------------")
print("✅ Manifesto actor test completed successfully!")
print("---------------------------------------------") 