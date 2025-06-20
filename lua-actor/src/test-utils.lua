-- Utility functions for testing Lua AO Actors

-- Extract relevant input details for error messages
local function getInputSummary(inputValue)
    if type(inputValue) == "string" then
        -- Try to parse as JSON
        local ok, parsed = pcall(function() return json.decode(inputValue) end)
        if ok and parsed.credentialSubject then
            return {
                inputId = parsed.credentialSubject.inputId,
                type = parsed.type and parsed.type[1],
                issuer = parsed.issuer and parsed.issuer.id
            }
        end
    end
    -- Return minimal info if we can't parse or it's not a VC
    return { raw = type(inputValue) == "string" and inputValue:sub(1, 50) .. "..." or tostring(inputValue) }
end

-- Format error message with relevant context
local function formatError(description, inputSummary, expected, actual)
    local parts = {
        "\n❌ TEST FAILED: " .. description,
        "Input: " .. (inputSummary.inputId or inputSummary.raw),
        "Expected: " .. expected,
        "Actual: " .. actual
    }
    if inputSummary.issuer then
        table.insert(parts, 2, "Issuer: " .. inputSummary.issuer)
    end
    return table.concat(parts, "\n  ")
end

-- Print a table recursively with nice formatting
local function printTable(t, indent)
  indent = indent or ""
  for k, v in pairs(t) do
    if type(v) == "table" then
      print(indent .. tostring(k) .. " = {")
      printTable(v, indent .. "  ")
      print(indent .. "}")
    else
      print(indent .. tostring(k) .. " = " .. tostring(v))
    end
  end
end

-- Compare two tables recursively by value
local function tablesEqual(t1, t2)
  -- If either isn't a table, compare directly
  if type(t1) ~= "table" or type(t2) ~= "table" then
    return t1 == t2
  end
  
  -- Check if all keys in t1 exist with same value in t2
  for k, v in pairs(t1) do
    if not tablesEqual(v, t2[k]) then
      return false
    end
  end
  
  -- Check if all keys in t2 exist in t1 (to catch extra keys in t2)
  for k in pairs(t2) do
    if t1[k] == nil then
      return false
    end
  end
  
  return true
end

-- Format boolean test results with colored output
local function formatResult(bool)
  if bool then
    return '\x1b[6;30;42m'..'SUCCESS'..'\x1b[0m'
  else
    return '\x1b[0;30;41m'..'FAILURE'..'\x1b[0m'
  end
end

-- Log a successful test with a checkmark
local function logTest(message, testCounter)
  if testCounter then
    testCounter.count = testCounter.count + 1
  end
  print("✅ PASSED: " .. message)
end

-- Helper function to run a test case for DFSM
local function runTest(description, dfsm, inputValue, expectedSuccess, expectedErrorContains, expectedState, DFSMUtils, testCounter, validateVC, debug)
    debug = debug or false
    
    print("\n---------------------------------------------")
    print("TEST: " .. description)
    
    -- Get input summary for error messages
    local inputSummary = getInputSummary(inputValue)
    
    -- Only print full input in debug mode
    if debug then
        print("Processing input: " .. tostring(inputValue))
    else
        print("Input: " .. (inputSummary.inputId or inputSummary.raw))
    end
    
    -- Process input
    local success, result = dfsm:processInput(inputValue, validateVC)
    
    -- Check success/failure
    if success ~= expectedSuccess then
        error(formatError(
            description,
            inputSummary,
            expectedSuccess and "success" or "failure",
            success and "success" or "failure: " .. tostring(result)
        ))
    end
    logTest("State machine " .. (expectedSuccess and "successfully processed" or "correctly rejected") .. " input", testCounter)
    
    -- Check error message if expected
    if not expectedSuccess and expectedErrorContains then
        if not result:find(expectedErrorContains, 1, true) then
            error(formatError(
                description,
                inputSummary,
                "error containing: " .. expectedErrorContains,
                "error: " .. tostring(result)
            ))
        end
        logTest("Error message contains expected text: " .. expectedErrorContains, testCounter)
    end
    
    -- Check state transition
    if expectedState then
        local currentState = dfsm.currentState and dfsm.currentState.id or "nil"
        if currentState ~= expectedState then
            error(formatError(
                description,
                inputSummary,
                "state: " .. expectedState,
                "state: " .. currentState
            ))
        end
        logTest("State machine transitioned to expected state: " .. expectedState, testCounter)
    end
    
    -- Only print full state in debug mode
    if debug then
        print(DFSMUtils.renderDFSMState(dfsm))
    else
        print("Current State: " .. (dfsm.currentState and dfsm.currentState.id or "nil"))
    end
end

local function loadInputDoc(path)
  -- Get the directory of the calling script (level 2 in the stack)
  local scriptPath = debug.getinfo(2, "S").source:sub(2)  -- Remove the @ prefix
  local scriptDir = scriptPath:match("(.*[/\\])") or "./"
  
  -- Normalize path separators to forward slashes
  path = path:gsub("\\", "/")
  
  -- If path starts with ./ or ../, it's a full relative path from the script's directory
  -- Otherwise, it's a local filename relative to the script's directory
  local fullPath
  if path:match("^%./") or path:match("^%.%./") then
    -- For paths starting with ./ or ../, use them relative to script's directory
    -- Remove the leading . and any leading slash to avoid double slashes
    fullPath = scriptDir .. path:gsub("^%.?/", "")
  else
    -- For local filenames, prepend the script's directory
    fullPath = scriptDir .. path
  end
  
  -- Try to open the file
  local file = io.open(fullPath, "r")
  if not file then
    error("Could not open input document file: " .. fullPath)
  end
  
  local content = file:read("*all")
  file:close()
  return content
end

-- Export the utility functions
return {
  printTable = printTable,
  tablesEqual = tablesEqual,
  formatResult = formatResult,
  logTest = logTest,
  runTest = runTest,
  loadInputDoc = loadInputDoc
}

