local Handlers = require("handlers")

local json = require("json")
local Array = require(".crypto.util.array")
local crypto = require(".crypto.init")
local utils = require(".utils")
local base64 = require(".base64")

local DFSM = require("dfsm")


-- BEGIN: actor's internal state
StateMachine = StateMachine or nil
Document = Document or nil
DocumentHash = DocumentHash or nil
DocumentOwner = DocumentOwner or nil
-- END: actor's internal state

-- Extension points for domain-specific functionality
local ExtensionPoints = {
  PRE_INIT = "pre_init",
  POST_INIT = "post_init",
  PRE_INPUT_PROCESSING = "pre_input_processing",
  POST_INPUT_PROCESSING = "post_input_processing",
  INPUT_VALIDATION = "input_validation",
  STATE_QUERY = "state_query"
}

-- Extension registry
local extensions = {}

-- Register an extension for a specific extension point
local function registerExtension(extensionPoint, handler)
  print("[apoc-v2] Registering extension for point:", extensionPoint)
  if not extensions[extensionPoint] then
    extensions[extensionPoint] = {}
  end
  table.insert(extensions[extensionPoint], handler)
  print("[apoc-v2] Total handlers for", extensionPoint, "=", #extensions[extensionPoint])
end

-- Execute all registered extensions for a given point
local function executeExtensions(extensionPoint, context)
  print("[apoc-v2] Executing extensions for point:", extensionPoint)
  local handlers = extensions[extensionPoint] or {}
  local results = {}
  
  for i, handler in ipairs(handlers) do
    print("[apoc-v2] Executing handler #", i, "for", extensionPoint)
    local success, result = pcall(handler, context)
    if success then
      table.insert(results, result)
    else
      print("[apoc-v2] Extension execution failed:", tostring(result))
      table.insert(results, { error = result })
    end
  end
  
  return results
end

-- Context builder for extension execution
local function buildContext(msg, stateMachine, customData)
  return {
    msg = msg,
    stateMachine = stateMachine,
    data = customData or {},
    timestamp = os.time()
  }
end

local function resetState()
  StateMachine = nil
  Document = nil
  DocumentHash = nil
  DocumentOwner = nil
  -- Don't clear extensions - they should persist across resets
  -- extensions = {}
end

local function reply_error(msg, error)
  msg.reply(
  {
    Data = {
      success = false,
      error = error
    }
  })
  print("Error during execution: " .. error)
  -- throwing errors seems to somehow get in the way of msg.reply going through, even though it happens strictly after...
  -- error(error_msg)
end

-- Enhanced input processor with extension support
local function processInputWithExtensions(msg)
  if not StateMachine then
    reply_error(msg, 'State machine not initialized')
    return false
  end
  
  local Data
  if type(msg.Data) == "string" then
    Data = json.decode(msg.Data)
  else
    Data = msg.Data
  end
  local inputValue = Data.inputValue
  
  print("[apoc-v2] processInputWithExtensions: inputValue type:", type(inputValue))
  
  -- Build context for extensions
  local context = buildContext(msg, StateMachine, {
    inputValue = inputValue,
    inputData = Data
  })
  
  -- Execute pre-processing extensions
  local preResults = executeExtensions(ExtensionPoints.PRE_INPUT_PROCESSING, context)
  
  -- Check for errors in pre-processing
  for _, result in ipairs(preResults) do
    if result.error then
      reply_error(msg, result.error)
      return false
    end
  end
  
  -- Execute input validation extensions
  local validationResults = executeExtensions(ExtensionPoints.INPUT_VALIDATION, context)
  
  -- Check for validation errors
  for _, result in ipairs(validationResults) do
    if result.error then
      reply_error(msg, result.error)
      return false
    end
  end
  
  print("[apoc-v2] processInputWithExtensions: Processing through DFSM...")
  -- Process through base DFSM
  local isValid, errorMsg = StateMachine:processInput(inputValue, true)
  
  print("[apoc-v2] processInputWithExtensions: DFSM result - isValid:", isValid, "errorMsg:", errorMsg)
  
  if not isValid then
    reply_error(msg, errorMsg or 'Failed to process input')
    return false
  end
  
  -- Execute post-processing extensions
  local postResults = executeExtensions(ExtensionPoints.POST_INPUT_PROCESSING, context)
  
  -- Check for errors in post-processing
  for _, result in ipairs(postResults) do
    if result.error then
      reply_error(msg, result.error)
      return false
    end
  end
  
  msg.reply({ Data = { success = true } })
  return true
end

-- Enhanced initialization with extension support
local function initializeWithExtensions(msg)
  print("[apoc-v2] Init handler called")
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
    print("[apoc-v2] Document already initialized!")
    reply_error(msg, 'Document is already initialized and cannot be overwritten')
    return false
  end
  
  -- Execute pre-init extensions
  local preContext = buildContext(msg, nil, { document = document })
  local preResults = executeExtensions(ExtensionPoints.PRE_INIT, preContext)
  
  -- Check for pre-init errors
  for _, result in ipairs(preResults) do
    if result and result.error then
      print("[apoc-v2] Pre-init extension error:", result.error)
      reply_error(msg, result.error)
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
    print("[apoc-v2] DFSM.new returned nil!")
    reply_error(msg, 'Invalid agreement document')
    return false
  end

  Document = type(document) == "string" and json.decode(document) or document
  DocumentHash = crypto.digest.keccak256(type(document) == "string" and document or json.encode(document)).asHex()
  print("[apoc-v2] Document hash set to:", DocumentHash)
  StateMachine = dfsm
  
  -- Execute post-init extensions
  local postContext = buildContext(msg, StateMachine, { document = Document })
  local postResults = executeExtensions(ExtensionPoints.POST_INIT, postContext)
  
  -- Check for post-init errors
  for _, result in ipairs(postResults) do
    if result and result.error then
      print("[apoc-v2] Post-init extension error:", result.error)
      reply_error(msg, result.error)
      return false
    end
  end

  msg.reply({ Data = { success = true } })
  return true
end

-- Enhanced state query with extension support
local function getStateWithExtensions(msg)
  if not StateMachine then
    reply_error(msg, 'State machine not initialized')
    return
  end

  local baseState = {
    State = StateMachine:getCurrentState(),
    IsComplete = StateMachine:isComplete(),
    Variables = StateMachine:getVariables(),
    Inputs = StateMachine:getInputs(),
    ReceivedInputs = StateMachine:getReceivedInputs(),
  }
  -- print(state)
  
  -- Execute state query extensions
  local context = buildContext(msg, StateMachine, { baseState = baseState })
  local queryResults = executeExtensions(ExtensionPoints.STATE_QUERY, context)
  
  -- Merge extension results into base state
  for _, result in ipairs(queryResults) do
    if result and type(result) == "table" then
      for key, value in pairs(result) do
        baseState[key] = value
      end
    end
  end
  
  msg.reply({ Data = baseState })
end

-- Base handlers
Handlers.add(
  "Init",
  Handlers.utils.hasMatchingTag("Action", "Init"),
  initializeWithExtensions
)

Handlers.add(
  "ProcessInput",
  Handlers.utils.hasMatchingTag("Action", "ProcessInput"),
  processInputWithExtensions
)

Handlers.add(
  "GetDocument",
  Handlers.utils.hasMatchingTag("Action", "GetDocument"),
  function (msg)
    msg.reply({ Data = {
        Document = Document,
        DocumentHash = DocumentHash,
        -- DocumentOwner = DocumentOwner,
    }})
  end
)

Handlers.add(
  "GetState",
  Handlers.utils.hasMatchingTag("Action", "GetState"),
  getStateWithExtensions
)

-- Export the extensible base actor
return { 
  Handlers = Handlers, 
  resetState = resetState,
  -- Extension framework
  ExtensionPoints = ExtensionPoints,
  registerExtension = registerExtension,
  executeExtensions = executeExtensions,
  buildContext = buildContext,
  -- Utility functions for extensions
  reply_error = reply_error
}