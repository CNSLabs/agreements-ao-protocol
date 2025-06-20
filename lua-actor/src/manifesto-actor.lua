local json = require("json")
local crypto = require(".crypto.init")

-- Import the extensible base actor
local BaseActor = require("apoc-v2")
local Handlers = BaseActor.Handlers

-- BEGIN: manifesto-specific state
Signers = Signers or {} -- Track signers: {address -> {name, timestamp, signatureHash}}
SignerCount = SignerCount or 0
-- END: manifesto-specific state

local function resetState()
  print("[manifesto-actor] resetState called")
  -- Reset base state
  BaseActor.resetState()
  -- Reset manifesto-specific state
  Signers = {}
  SignerCount = 0
  print("[manifesto-actor] Signers and SignerCount reset")
end

-- Manifesto-specific extension functions
local function setupManifestoExtensions()
  print("[manifesto-actor] Registering extensions...")
  -- Pre-init: Initialize manifesto-specific state
  BaseActor.registerExtension(BaseActor.ExtensionPoints.PRE_INIT, function(context)
    print("[manifesto-actor] PRE_INIT extension called")
    Signers = {}
    SignerCount = 0
    print("[manifesto-actor] PRE_INIT: Signers and SignerCount reset")
    return { success = true }
  end)
  
  -- Input validation: Validate manifesto signatures
  BaseActor.registerExtension(BaseActor.ExtensionPoints.INPUT_VALIDATION, function(context)
    print("[manifesto-actor] INPUT_VALIDATION extension called")
    local inputValue = context.data.inputValue
    
    print("[manifesto-actor] INPUT_VALIDATION: inputValue type:", type(inputValue))
    
    -- Parse the input to extract signer information
    local vcJson
    if type(inputValue) == "string" then
      print("[manifesto-actor] INPUT_VALIDATION: inputValue is string, decoding...")
      vcJson = json.decode(inputValue)
    else
      print("[manifesto-actor] INPUT_VALIDATION: inputValue is table, using directly")
      vcJson = inputValue
    end
    
    print("[manifesto-actor] INPUT_VALIDATION: vcJson type:", type(vcJson))
    
    -- Support both VC and credentialSubject-only formats
    local credentialSubject = vcJson.credentialSubject or vcJson
    local inputId = credentialSubject.inputId
    
    print("[manifesto-actor] INPUT_VALIDATION: inputId:", inputId)
    
    -- Handle manifesto-specific validation
    if inputId == "signManifesto" then
      local signerName = credentialSubject.values and credentialSubject.values.signerName
      local signerAddress = credentialSubject.values and credentialSubject.values.signerAddress
      
      print("[manifesto-actor] INPUT_VALIDATION: signerName:", signerName)
      print("[manifesto-actor] INPUT_VALIDATION: signerAddress:", signerAddress)
      
      if not signerName or not signerAddress then
        print("[manifesto-actor] INPUT_VALIDATION: missing name or address")
        return { error = 'Missing signer name or address in manifesto signature' }
      end
      
      -- Check if signer already signed
      local normalizedAddress = string.lower(signerAddress)
      if Signers[normalizedAddress] then
        print("[manifesto-actor] INPUT_VALIDATION: duplicate signer", normalizedAddress)
        return { error = 'Signer has already signed the manifesto' }
      end
      
      print("[manifesto-actor] INPUT_VALIDATION: validation passed")
    end
    
    return { success = true }
  end)
  
  -- Post-input processing: Track signers after successful processing
  BaseActor.registerExtension(BaseActor.ExtensionPoints.POST_INPUT_PROCESSING, function(context)
    print("[manifesto-actor] POST_INPUT_PROCESSING extension called")
    local inputValue = context.data.inputValue
    
    print("[manifesto-actor] POST_INPUT_PROCESSING: inputValue type:", type(inputValue))
    
    -- Parse the input to extract signer information
    local vcJson
    if type(inputValue) == "string" then
      print("[manifesto-actor] POST_INPUT_PROCESSING: inputValue is string, decoding...")
      vcJson = json.decode(inputValue)
    else
      print("[manifesto-actor] POST_INPUT_PROCESSING: inputValue is table, using directly")
      vcJson = inputValue
    end
    
    local credentialSubject = vcJson.credentialSubject
    local inputId = credentialSubject.inputId
    
    print("[manifesto-actor] POST_INPUT_PROCESSING: inputId:", inputId)
    
    -- Handle manifesto-specific post-processing
    if inputId == "signManifesto" then
      local signerName = credentialSubject.values.signerName
      local signerAddress = credentialSubject.values.signerAddress
      
      print("[manifesto-actor] POST_INPUT_PROCESSING: Processing signer", signerName, signerAddress)
      
      -- Track the signer
      local normalizedAddress = string.lower(signerAddress)
      local inputValueStr = type(inputValue) == "string" and inputValue or json.encode(inputValue)
      local signatureHash = crypto.digest.keccak256(inputValueStr).asHex()
      
      Signers[normalizedAddress] = {
        name = signerName,
        address = signerAddress,
        timestamp = os.time(),
        signatureHash = signatureHash
      }
      SignerCount = SignerCount + 1
      print("[manifesto-actor] POST_INPUT_PROCESSING: Added signer", normalizedAddress, "SignerCount:", SignerCount)
    end
    
    return { success = true }
  end)
  
  -- State query: Add manifesto-specific state to queries
  BaseActor.registerExtension(BaseActor.ExtensionPoints.STATE_QUERY, function(context)
    print("[manifesto-actor] STATE_QUERY extension called. SignerCount:", SignerCount)
    return {
      SignerCount = SignerCount,
      Signers = Signers
    }
  end)
end

-- Manifesto-specific handlers (only the new ones)
local ManifestoHandlers = {}

-- Setup extensions when the module is loaded
setupManifestoExtensions()

-- Add manifesto-specific handlers to the base Handlers object
for _, handler in ipairs(ManifestoHandlers) do
  Handlers.add(
    handler.name or "ManifestoHandler",
    handler.predicate,
    handler.handler
  )
end

print("[manifesto-actor] Added", #ManifestoHandlers, "manifesto handlers to base Handlers")

return { 
  Handlers = Handlers, 
  resetState = resetState 
} 