-- Actor Extensions Library
-- Provides extension point functionality for actor customization

local json = require("json")

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
      print("[actor-extensions] Extension execution failed:", tostring(result))
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

-- Helper function to check for errors in extension results
local function checkExtensionErrors(results, errorCallback)
  for _, result in ipairs(results) do
    if result and result.error then
      errorCallback(result.error)
      return true -- error found
    end
  end
  return false -- no errors
end

-- Helper function to merge extension results into a base state
local function mergeExtensionResults(baseState, results)
  for _, result in ipairs(results) do
    if result and type(result) == "table" then
      for key, value in pairs(result) do
        baseState[key] = value
      end
    end
  end
  return baseState
end

return {
  ExtensionPoints = ExtensionPoints,
  registerExtension = registerExtension,
  executeExtensions = executeExtensions,
  buildContext = buildContext,
  checkExtensionErrors = checkExtensionErrors,
  mergeExtensionResults = mergeExtensionResults
} 