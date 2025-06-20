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
  
  -- Post-init: Override document hash calculation to match DFSM method
  BaseActor.registerExtension(BaseActor.ExtensionPoints.POST_INIT, function(context)
    print("[manifesto-actor] POST_INIT extension called")
    -- Override the DocumentHash to use the DFSM method (hash of entire wrapped VC)
    if context.data and context.data.originalDocument then
      DocumentHash = crypto.digest.keccak256(type(context.data.originalDocument) == "string" and context.data.originalDocument or json.encode(context.data.originalDocument)).asHex()
      print("[manifesto-actor] POST_INIT: DocumentHash overridden to:", DocumentHash)
    end
    return { success = true }
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

-- Enhanced initialization with extension support
local function initializeWithExtensions(msg)
  print("[manifesto-actor] Init handler called")
  local Data
  if type(msg.Data) == "string" then
    Data = json.decode(msg.Data)
  else
    Data = msg.Data
  end
  
  -- Handle both old format (document as string) and new format (structured message)
  local document, initialValues
  if Data.document then
    document = Data.document -- already a string
    initialValues = Data.initialValues or {}
  else
    document = Data
    initialValues = {}
    
    -- Extract initial values from wrapped VC params if available
    if type(document) == "table" and document.credentialSubject and document.credentialSubject.params then
      for key, value in pairs(document.credentialSubject.params) do
        initialValues[key] = value
      end
    end
  end

  -- If document is a string, check if it's a wrapped VC and extract the agreement
  local originalDocument = document -- Keep the original for hash calculation
  if type(document) == "string" then
    local parsed = json.decode(document)
    if parsed.credentialSubject and parsed.credentialSubject.agreement then
      -- Wrapped VC: extract and decode agreement
      local agreementBase64 = parsed.credentialSubject.agreement
      local agreementJson = base64.decode(agreementBase64)
      document = agreementJson
    end
  elseif type(document) == "table" then
    -- Check if the document itself is a wrapped VC
    if document.credentialSubject and document.credentialSubject.agreement then
      -- Wrapped VC: extract and decode agreement
      local agreementBase64 = document.credentialSubject.agreement
      local agreementJson = base64.decode(agreementBase64)
      document = agreementJson
    end
  end

  if Document then
    print("[manifesto-actor] Document already initialized!")
    BaseActor.reply_error(msg, 'Document is already initialized and cannot be overwritten')
    return false
  end
  
  -- Execute pre-init extensions
  local preContext = BaseActor.buildContext(msg, nil, { document = document })
  local preResults = BaseActor.executeExtensions(BaseActor.ExtensionPoints.PRE_INIT, preContext)
  
  -- Check for pre-init errors
  for _, result in ipairs(preResults) do
    if result and result.error then
      print("[manifesto-actor] Pre-init extension error:", result.error)
      BaseActor.reply_error(msg, result.error)
      return false
    end
  end
  
  -- Extract initial variable values for DFSM (fallback to document.variables if not provided)
  if not initialValues or not next(initialValues) then
    local docTable = type(document) == "string" and json.decode(document) or document
    if docTable.variables then
      for varName, varDef in pairs(docTable.variables) do
        if varDef.value ~= nil then
          initialValues[varName] = varDef.value
        end
      end
    end
  end
  
  -- Ensure document is a string for DFSM.new
  local documentString = type(document) == "string" and document or json.encode(document)
  local dfsm = DFSM.new(documentString, false, initialValues)

  if not dfsm then
    print("[manifesto-actor] DFSM.new returned nil!")
    BaseActor.reply_error(msg, 'Invalid agreement document')
    return false
  end

  Document = type(document) == "string" and json.decode(document) or document
  -- Use the DFSM's hash calculation method (hash of entire wrapped VC document)
  DocumentHash = crypto.digest.keccak256(type(originalDocument) == "string" and originalDocument or json.encode(originalDocument)).asHex()
  print("[manifesto-actor] Document hash set to:", DocumentHash)
  StateMachine = dfsm
  
  -- Execute post-init extensions
  local postContext = BaseActor.buildContext(msg, StateMachine, { document = Document })
  local postResults = BaseActor.executeExtensions(BaseActor.ExtensionPoints.POST_INIT, postContext)
  
  -- Check for post-init errors
  for _, result in ipairs(postResults) do
    if result and result.error then
      print("[manifesto-actor] Post-init extension error:", result.error)
      BaseActor.reply_error(msg, result.error)
      return false
    end
  end

  msg.reply({ Data = { success = true } })
  return true
end

return { 
  Handlers = Handlers, 
  resetState = resetState 
} 