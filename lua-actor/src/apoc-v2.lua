local Handlers = require("handlers")
local ActorExtensions = require("actor-extensions")

local json = require("json")
local crypto = require(".crypto.init")
local base64 = require(".base64")

local DFSM = require("dfsm")

-- BEGIN: actor's internal state
StateMachine = StateMachine or nil
Document = Document or nil
DocumentHash = DocumentHash or nil
DocumentOwner = DocumentOwner or nil
-- END: actor's internal state

local function resetState()
  StateMachine = nil
  Document = nil
  DocumentHash = nil
  DocumentOwner = nil
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
  local context = ActorExtensions.buildContext(msg, StateMachine, {
    inputValue = inputValue,
    inputData = Data
  })
  
  -- Execute pre-processing extensions
  local preResults = ActorExtensions.executeExtensions(ActorExtensions.ExtensionPoints.PRE_INPUT_PROCESSING, context)
  
  -- Check for errors in pre-processing
  if ActorExtensions.checkExtensionErrors(preResults, function(error) 
    msg.reply({ Data = { success = false, error = error } })
  end) then
    return false
  end
  
  -- Execute input validation extensions
  local validationResults = ActorExtensions.executeExtensions(ActorExtensions.ExtensionPoints.INPUT_VALIDATION, context)
  
  -- Check for validation errors
  if ActorExtensions.checkExtensionErrors(validationResults, function(error) 
    msg.reply({ Data = { success = false, error = error } })
  end) then
    return false
  end
  
  -- Process through base DFSM
  local isValid, errorMsg = StateMachine:processInput(inputValue, true)
  
  if not isValid then
    msg.reply({ Data = { success = false, error = errorMsg or 'Failed to process input' } })
    return false
  end
  
  -- Execute post-processing extensions
  local postResults = ActorExtensions.executeExtensions(ActorExtensions.ExtensionPoints.POST_INPUT_PROCESSING, context)
  
  -- Check for errors in post-processing
  if ActorExtensions.checkExtensionErrors(postResults, function(error) 
    msg.reply({ Data = { success = false, error = error } })
  end) then
    return false
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
  local preContext = ActorExtensions.buildContext(msg, nil, { document = agreementJson })
  local preResults = ActorExtensions.executeExtensions(ActorExtensions.ExtensionPoints.PRE_INIT, preContext)
  
  -- Check for pre-init errors
  if ActorExtensions.checkExtensionErrors(preResults, function(error) reply_error(msg, error) end) then
    return false
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
  local postContext = ActorExtensions.buildContext(msg, StateMachine, { document = Document })
  local postResults = ActorExtensions.executeExtensions(ActorExtensions.ExtensionPoints.POST_INIT, postContext)
  
  -- Check for post-init errors
  if ActorExtensions.checkExtensionErrors(postResults, function(error) reply_error(msg, error) end) then
    return false
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
  
  -- Execute state query extensions
  local context = ActorExtensions.buildContext(msg, StateMachine, { baseState = baseState })
  local queryResults = ActorExtensions.executeExtensions(ActorExtensions.ExtensionPoints.STATE_QUERY, context)
  
  -- Merge extension results into base state
  baseState = ActorExtensions.mergeExtensionResults(baseState, queryResults)
  
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
  -- Extension framework (delegated to ActorExtensions library)
  ExtensionPoints = ActorExtensions.ExtensionPoints,
  registerExtension = ActorExtensions.registerExtension,
  executeExtensions = ActorExtensions.executeExtensions,
  buildContext = ActorExtensions.buildContext,
  -- Utility functions for extensions
  reply_error = reply_error
}