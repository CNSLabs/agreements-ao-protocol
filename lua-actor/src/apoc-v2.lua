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
  if not extensions[extensionPoint] then
    extensions[extensionPoint] = {}
  end
  table.insert(extensions[extensionPoint], handler)
end

-- Execute all registered extensions for a given point
local function executeExtensions(extensionPoint, context)
  local handlers = extensions[extensionPoint] or {}
  local results = {}
  
  for i, handler in ipairs(handlers) do
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
  
  -- Process through base DFSM
  local isValid, errorMsg = StateMachine:processInput(inputValue, true)
  
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
  local Data
  if type(msg.Data) == "string" then
    Data = json.decode(msg.Data)
  else
    Data = msg.Data
  end
  
  -- Always expect wrapped VC format
  local document = msg.Data -- Keep original wrapped VC for hash calculation
  local initialValues = {}
  
  -- Extract initial values from wrapped VC params
  if Data.credentialSubject and Data.credentialSubject.params then
    for key, value in pairs(Data.credentialSubject.params) do
      initialValues[key] = value
    end
  end

  -- Extract agreement JSON from wrapped VC for DFSM processing
  local agreementJson
  if Data.credentialSubject and Data.credentialSubject.agreement then
    local agreementBase64 = Data.credentialSubject.agreement
    agreementJson = base64.decode(agreementBase64)
  else
    reply_error(msg, 'Invalid wrapped VC: missing credentialSubject.agreement')
    return false
  end

  if Document then
    reply_error(msg, 'Document is already initialized and cannot be overwritten')
    return false
  end
  
  -- Execute pre-init extensions
  local preContext = buildContext(msg, nil, { document = agreementJson })
  local preResults = executeExtensions(ExtensionPoints.PRE_INIT, preContext)
  
  -- Check for pre-init errors
  for _, result in ipairs(preResults) do
    if result and result.error then
      reply_error(msg, result.error)
      return false
    end
  end
  
  -- Extract initial variable values for DFSM (fallback to document.variables if not provided)
  if not initialValues or not next(initialValues) then
    local docTable = json.decode(agreementJson)
    if docTable.variables then
      for varName, varDef in pairs(docTable.variables) do
        if varDef.value ~= nil then
          initialValues[varName] = varDef.value
        end
      end
    end
  end
  
  -- Initialize DFSM with wrapped VC (expectVCWrapper = true)
  local dfsm = DFSM.new(document, true, initialValues)

  if not dfsm then
    reply_error(msg, 'Invalid agreement document')
    return false
  end

  Document = json.decode(agreementJson)
  -- Calculate document hash from the original wrapped VC document
  DocumentHash = crypto.digest.keccak256(document).asHex()
  StateMachine = dfsm
  
  -- Execute post-init extensions
  local postContext = buildContext(msg, StateMachine, { document = Document })
  local postResults = executeExtensions(ExtensionPoints.POST_INIT, postContext)
  
  -- Check for post-init errors
  for _, result in ipairs(postResults) do
    if result and result.error then
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