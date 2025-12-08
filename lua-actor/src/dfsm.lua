-- DFSM (Deterministic Finite State Machine) implementation
local VariableManager = require("variables.variable_manager")
local InputVerifier = require("verifiers.input_verifier")
local json = require("json")
local VcValidator = require("vc-validator")
local ContractManager = require("contracts.contract_manager")
local base64 = require(".base64")
local crypto = require(".crypto.init")

local ValidationUtils = InputVerifier.ValidationUtils

-- DFSM class definition
local DFSM = {}

-- Helper function to check if a transition's conditions are met
function DFSM:areTransitionConditionsMet(transition, inputId)
    for _, condition in ipairs(transition.conditions) do
        if condition.type == "isValid" then
            if condition.input == inputId then
                return true
            end
        end
    end
    return #transition.conditions == 0
end

-- Helper function to check if a state has outgoing transitions
function DFSM:hasOutgoingTransitions(stateId)
    for _, t in ipairs(self.transitions) do
        if t.from == stateId then
            return true
        end
    end
    return false
end

-- Helper function to check if a state has incoming transitions
function DFSM:hasIncomingTransitions(stateId)
    for _, t in ipairs(self.transitions) do
        if t.to == stateId then
            return true
        end
    end
    return false
end

-- Helper function to validate initialParams against initialValues
function DFSM:validateInitialParams(stateId, initialParams, initialValues)
    if not initialParams or type(initialParams) ~= "table" then
        return true
    end

    if not initialValues then
        error("Initial state " .. stateId .. " requires parameters, but no initial values provided")
    end

    -- Validate the variable values against variable definitions
    local isValid, errorMsg = ValidationUtils.processAndValidateVariables(initialParams, initialValues, self)
    if not isValid then
        error("Invalid parameter value for state " .. stateId .. ": " .. errorMsg)
    end

    return true
end

-- Helper function to validate initialization data
function DFSM:validateInitialization(initialization, initialValues)
    if not initialization then
        return true
    end

    if not initialValues then
        error("Initialization data provided but no initial values provided")
    end

    -- Validate the variable values against variable definitions
    local isValid, errorMsg = ValidationUtils.processAndValidateVariables(initialization.data, initialValues, self)
    if not isValid then
        error("Invalid initialization value: " .. errorMsg)
    end

    return true
end

-- Initialize a new DFSM instance from a JSON definition
function DFSM.new(doc, expectVCWrapper, params)
    local self = {
        currentState = nil, -- Will store the entire state object
        inputs = {},
        transitions = {},
        variables = nil,
        contracts = nil,
        receivedInputValues = {},
        complete = false,
        states = {}, -- Store state information (name, description)
        documentHash = nil,
    }

    -- Allow skipping VC wrapper processing if not needed for testing
    local agreement = nil
    local initialValues = nil
    if expectVCWrapper then
        -- The agreement template VC is expected to base64 encode the agreement contents
        -- to simplify EIP-712 encoding.
        local credentialSubject = DFSM:processVCWrapper(doc, nil, true)
        agreement = json.decode(base64.decode(credentialSubject.agreement))
        initialValues = credentialSubject.params
    else
        agreement = json.decode(doc)
        initialValues = params
    end

    -- Initialize variables
    self.variables = VariableManager.new(agreement.variables)
    self.contracts = ContractManager.new(agreement.contracts or {})
    self.documentHash = crypto.digest.keccak256(doc).asHex()

    -- Set metatable early so methods can be called
    setmetatable(self, { __index = DFSM })

    -- Validate agreement structure before processing
    if not agreement.execution or not agreement.execution.states then
        error("Agreement document must have states defined")
    end
    if type(agreement.execution.states) ~= "table" then
        error("States must be defined as an object")
    end
    if agreement.execution.initialize then
        if not agreement.execution.initialize.data then
            error("Initialization section must contain a 'data' field")
        end
        if not agreement.execution.initialize.initialState then
            error("Initialization section must specify an initialState")
        end
        -- Store the initial state from the initialize section
        self.initialState = agreement.execution.initialize.initialState
    else
        error("Agreement document must have an initialize section with initialState")
    end
    if agreement.execution.inputs and type(agreement.execution.inputs) ~= "table" then
        error("Inputs must be an object with input IDs as keys")
    end

    -- Process states - only support object format
    for stateId, stateObj in pairs(agreement.execution.states) do
        self.states[stateId] = {
            id = stateId, -- Include the ID in the state object for reference
            name = stateObj.name or stateId,
            description = stateObj.description or "",
            initialParams = stateObj.initialParams or {}
        }
    end

    -- Process inputs (assuming object structure)
    if agreement.execution.inputs then
        for id, input in pairs(agreement.execution.inputs) do
            self.inputs[id] = input
        end
    end

    -- Process transitions
    if agreement.execution.transitions then
        for _, transition in ipairs(agreement.execution.transitions) do
            table.insert(self.transitions, transition)
        end
    end

    -- Validate the state machine and get initial state
    local initialStateId = self:validate()
    self.currentState = self.states[initialStateId]

    -- Validate and process initialization data if provided
    if agreement.execution.initialize then
        self:validateInitialization(agreement.execution.initialize, initialValues)
        -- Set initial values if provided
        if initialValues then
            for id, value in pairs(initialValues) do
                if self.variables:isVariable(id) then
                    local success, err = pcall(function() self.variables:setVariable(id, value) end)

                    print(self.variables:getVariable(id));

                    if not success then
                        error(string.format("Error setting variable '%s' to '%s': %s", id, tostring(value), err))
                    end
                else
                    error(string.format("Attempted to set undeclared variable: %s", id))
                end
            end
        end
    end

    return self
end

-- process VC wrapper
function DFSM:processVCWrapper(vc, expectedIssuer, validateVC)
    -- validate by default
    validateVC = validateVC == nil or validateVC
    if validateVC then
        local success, vcJson, ownerAddress = VcValidator.validate(vc)
        assert(success, "Invalid VC");

        if expectedIssuer then
            if not ValidationUtils.ethAddressEqual(ownerAddress, expectedIssuer) then
                local errorMsg = string.format("Issuer mismatch: expected ${variables.partyAEthAddress.value}, got %s",
                    ownerAddress)
                error(errorMsg)
            end
        end
        return vcJson.credentialSubject
    else
        local vcJson = json.decode(vc)
        return vcJson.credentialSubject or vcJson
    end
end

-- Validate the state machine definition
function DFSM:validate()
    -- Check that we have at least one state
    if not next(self.states) then
        error("Agreement document must have states defined")
    end

    -- Use the explicitly specified initial state
    local initialStateId = self.initialState
    if not self.states[initialStateId] then
        error(string.format("Specified initial state '%s' does not exist in states definition", initialStateId))
    end

    -- Check that all states referenced in transitions exist
    for _, transition in ipairs(self.transitions) do
        if not self.states[transition.from] then
            error(string.format("Invalid 'from' state in transition: %s", transition.from))
        end
        if not self.states[transition.to] then
            error(string.format("Invalid 'to' state in transition: %s", transition.to))
        end
    end

    -- Check that all inputs referenced in conditions exist
    local validInputs = {}
    for inputId, _ in pairs(self.inputs) do
        validInputs[inputId] = true
    end

    for _, transition in ipairs(self.transitions) do
        for _, condition in ipairs(transition.conditions) do
            if condition.type == "isValid" then
                if condition.input and not validInputs[condition.input] then
                    error(string.format("Invalid input referenced in condition: %s", condition.input))
                end
                if condition.inputs then
                    for _, inputId in ipairs(condition.inputs) do
                        if not validInputs[inputId] then
                            error(string.format("Invalid input referenced in condition: %s", inputId))
                        end
                    end
                end
            end
        end
    end

    -- Validate input schemas
    for inputId, input in pairs(self.inputs) do
        if not input.type then
            error(string.format("Input %s missing type", inputId))
        end
        if not input.schema then
            error(string.format("Input %s missing schema", inputId))
        end
    end

    return initialStateId
end

-- Process an input and attempt to transition states
function DFSM:processInput(inputValue, validateVC)
    if self.complete then
        return false, "State machine is complete"
    end

    -- Parse the VC if it's a string
    local vcJson
    if type(inputValue) == "string" then
        vcJson = json.decode(inputValue)
    else
        vcJson = inputValue
    end

    -- Extract inputId from the VC
    local credentialSubject = vcJson.credentialSubject
    if not credentialSubject or not credentialSubject.inputId then
        return false, "Input VC missing credentialSubject.inputId"
    end
    local inputId = credentialSubject.inputId

    -- Get input definition
    local inputDef = self:getInput(inputId)
    if not inputDef then
        return false, string.format("Unknown input: %s", inputId)
    end

    -- For tests, we set validateVC=false to bypass cryptographic validation
    -- For production, validateVC should be true to ensure proper signature validation
    
    -- Verify input type and schema
    local isValid, result = InputVerifier.verify(inputDef, inputValue, self, validateVC)
    if not isValid then
        return false, result
    end

    -- Process transitions from current state
    for _, transition in ipairs(self.transitions) do
        if transition.from == self.currentState.id then
            -- Note, because we previously validated the input, we can just check if the inputId is in the transition.conditions.inputs
            if self:areTransitionConditionsMet(transition, inputId) then
                -- Update variables with the verified values only if transition occurs
                if type(result) == "table" then
                    for id, value in pairs(result) do
                        if self.variables:isVariable(id) then
                            self.variables:setVariable(id, value)
                        end
                    end
                end
                
                -- Store only the hash and issuer instead of the full input
                local inputValueStr = type(inputValue) == "string" and inputValue or json.encode(inputValue)
                local inputHash = crypto.digest.keccak256(inputValueStr).asHex()
                local issuerId = vcJson.issuer and vcJson.issuer.id or "unknown"
                
                table.insert(self.receivedInputValues, {
                    id = inputId, 
                    hash = inputHash,
                    issuer = issuerId,
                    timestamp = os.time()
                })
                
                self.currentState = self.states[transition.to]
                
                -- Check if we've reached a terminal state
                if not self:hasOutgoingTransitions(self.currentState.id) then
                    self.complete = true
                end
                return true, "Transition successful"
            end
        end
    end

    return false, "No valid transition found"
end

-- Get the current state ID
function DFSM:getCurrentStateId()
    return self.currentState.id
end

-- Get the current state object
function DFSM:getCurrentState()
    return self.currentState
end

-- Get details for a specific state
function DFSM:getStateDetails(stateId)
    return self.states[stateId]
end

-- Get all states
function DFSM:getAllStates()
    return self.states
end

-- Check if the state machine is complete
function DFSM:isComplete()
    return self.complete
end

-- Get all received inputs as a stack
function DFSM:getReceivedInputs()
    return self.receivedInputValues
end

-- Get the most recent input hash for a specific input ID
function DFSM:getLatestInputHash(inputId)
    -- Search from the top of the stack (most recent) down
    for i = #self.receivedInputValues, 1, -1 do
        local input = self.receivedInputValues[i]
        if input.id == inputId then
            return input.hash
        end
    end
    return nil -- No input found with that ID
end

-- Get the most recent input metadata for a specific input ID
function DFSM:getLatestInputMetadata(inputId)
    -- Search from the top of the stack (most recent) down
    for i = #self.receivedInputValues, 1, -1 do
        local input = self.receivedInputValues[i]
        if input.id == inputId then
            return {
                hash = input.hash,
                issuer = input.issuer,
                timestamp = input.timestamp
            }
        end
    end
    return nil -- No input found with that ID
end

-- Check if a specific input has been received
function DFSM:hasReceivedInput(inputId)
    return self:getLatestInputHash(inputId) ~= nil
end

-- Get all received input hashes as a map of inputId to its most recent hash
function DFSM:getReceivedInputHashesMap()
    local result = {}
    for i = 1, #self.receivedInputValues do
        local input = self.receivedInputValues[i]
        -- This will naturally keep overwriting with the latest value for each ID
        result[input.id] = {
            hash = input.hash,
            issuer = input.issuer,
            timestamp = input.timestamp
        }
    end
    return result
end

-- Get a variable value
function DFSM:getVariable(name)
    return self.variables:getVariable(name)
end

-- Set a variable value
function DFSM:setVariable(name, value)
    self.variables:setVariable(name, value)
end

-- Get all variables
function DFSM:getVariables()
    return self.variables:getAllVariables()
end

-- Get input definition by ID
function DFSM:getInput(inputId)
    return self.inputs[inputId]
end

-- Get all inputs
function DFSM:getInputs()
    return self.inputs
end

-- Export the DFSM module
return {
    new = DFSM.new,
}
