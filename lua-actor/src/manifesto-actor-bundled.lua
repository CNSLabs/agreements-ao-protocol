-- TODO: BEGIN remove lines before copying the actor logic into the backend service
local Handlers = require("Handlers")
local secp256k1 = require("secp256k1")
local recover_public_key = secp256k1.recover_public_key
-- TODO: END remove lines

-- Module definitions
local __modules = {}
local __loaded = {}

-- Begin module: eip712.lua
__modules["eip712"] = function()
  if __loaded["eip712"] then return __loaded["eip712"] end
local crypto = require(".crypto.init")
local Array = require(".crypto.util.array")

-- A pure Lua implementation of the EIP-712 encoding logic. Used in actor logic to validate VCs using 

-- Forward declarations for functions with circular dependencies
local encodeParameter
local isDynamicType
local encodeField
local encodeData
local hashStruct

local function padLeft(str, length, char)
    char = char or '0'
    local padding = string.rep(char, length - #str)
    return padding .. str
end

local function padRight(str, length, char)
    char = char or '0'
    local padding = string.rep(char, length - #str)
    return str .. padding
end

-- Basic type encoders
local function encodeUint256(value)
    local hex = string.format("%x", value)
    return padLeft(hex, 64)
end

local function encodeAddress(value)
    value = string.gsub(value, "^0x", "")
    return padLeft(value, 64)
end

local function encodeBool(value)
    return encodeUint256(value and 1 or 0)
end

local function encodeBytes(value)
  local length = encodeUint256(#value)
  local paddedData = value .. string.rep(string.char(0), (32 - (#value % 32)) % 32)
  return length .. paddedData
end

local function encodeFixedBytes(value, size)
    if #value > size * 2 then -- hex string expected, 2 hex chars per byte
        error(string.format("Value too long for bytes%d: got %d bytes", size, #value))
    end
    return value .. string.rep(string.char(0), size - #value)
end

local function encodeString(value)
    local bytes = string.char(string.byte(value, 1, -1))
    return encodeBytes(bytes)
end

local function encodeArray(baseType, array, size, types)
    local result = ""
    if #size == 0 then
        result = encodeUint256(#array)
    end
    
    -- For arrays of structs, we need to hash each item first
    if types and types[baseType] then
        for _, value in ipairs(array) do
            local hash = hashStruct(baseType, value, types)
            result = result .. encodeParameter("bytes32", hash, types)
        end
    else
        -- For primitive arrays, encode directly
        for _, value in ipairs(array) do
            result = result .. encodeParameter(baseType, value, types)
        end
    end
    
    return result
end

function isDynamicType(typ)
    -- Check for basic dynamic types
    if typ == "string" or typ == "bytes" then
        return true
    end
    
    -- Check for fixed-size bytes (bytes1 to bytes32)
    local bytesMatch = string.match(typ, "^bytes(%d+)$")
    if bytesMatch then
        local size = tonumber(bytesMatch)
        if size then
            return false  -- Fixed-size bytes are static
        end
        error("Invalid bytes size: " .. bytesMatch)
    end
    
    -- Check for arrays - pattern needs to handle the full type including numbers
    local baseType, size = string.match(typ, "^([%a%d]+)%[(%d*)%]$")
    if baseType then
        -- Dynamic if it's an unbounded array or contains dynamic types
        return #size == 0 or isDynamicType(baseType)
    end
    
    return false
end


-- Parameter encoding
function encodeParameter(typ, value, types)
    if typ == "uint256" then
        return encodeUint256(value)
    elseif typ == "address" then
        return encodeAddress(value)
    elseif typ == "bool" then
        return encodeBool(value)
    elseif typ == "string" then
        return encodeString(value)
    elseif typ == "bytes" then
        return encodeBytes(value)
    end
    
    -- Handle fixed-size bytes
    local bytesMatch = string.match(typ, "^bytes(%d+)$")
    if bytesMatch then
        local size = tonumber(bytesMatch)
        if size then
            return encodeFixedBytes(value, size)
        end
    end

    local baseType, size = string.match(typ, "^([%a%d]+)%[(%d*)%]$")
    if baseType then
        return encodeArray(baseType, value, size, types)
    end
    
    error("Unsupported type: " .. typ)
end

-- ABI encoding
local function abiEncode(types, values, eip712types)
    local headLength = 0
    local heads = {}
    local tails = {}
    local dynamicCount = 0
    
    for i, typ in ipairs(types) do
        local value = values[i]
        
        if isDynamicType(typ) then
            table.insert(heads, "")
            dynamicCount = dynamicCount + 1
        else
            local encoded = encodeParameter(typ, value, eip712types)
            table.insert(heads, encoded)
        end
        
        headLength = headLength + 32
    end
    
    local currentDynamicPointer = headLength
    for i, typ in ipairs(types) do
        if isDynamicType(typ) then
            local value = values[i]
            local encoded = encodeParameter(typ, value, eip712types)
            
            heads[i] = encodeUint256(currentDynamicPointer)
            table.insert(tails, encoded)
            
            currentDynamicPointer = currentDynamicPointer + #encoded
        end
    end
    
    return table.concat(heads) .. table.concat(tails)
end

-- EIP-712 specific functions
local function keccak256(input)
    return crypto.digest.keccak256(input).asHex()
end

local function findTypeDependenciesWorker(typeName, types, deps)
    deps = deps or {}
    
    if not deps[typeName] then
        deps[typeName] = true
        
        for _, field in ipairs(types[typeName]) do
            -- Match both struct types and arrays of struct types with a single pattern
            -- e.g., 'CredentialSubject' or 'Fields[]'
            local match = string.match(field.type, "^([A-Z][A-Za-z0-9]*)%[?%]?$")
            if match then
                findTypeDependenciesWorker(match, types, deps)
            end
        end
    end
    
    return deps
end

local function findTypeDependencies(typeName, types)
    -- First discover all dependencies
    local deps = findTypeDependenciesWorker(typeName, types)
    
    -- Then convert to array format
    local result = {}
    for dep in pairs(deps) do
        table.insert(result, dep)
    end
    return result
end

local function encodeParameters(type)
    local params = {}
    for _, param in ipairs(type) do
        table.insert(params, param.type .. " " .. param.name)
    end
    return table.concat(params, ",")
end

local function encodeType(typeName, types)
    local deps = findTypeDependencies(typeName, types)
    local index
    for i, v in ipairs(deps) do
        if v == typeName then
            index = i
            break
        end
    end
    table.remove(deps, index)
    table.sort(deps)
    table.insert(deps, 1, typeName)
    
    local encodedTypes = ""
    for _, dep in ipairs(deps) do
        local type = types[dep]
        encodedTypes = encodedTypes .. dep .. "(" .. encodeParameters(type) .. ")"
    end
    
    return encodedTypes
end

local function typeHash(typeName, types)
    return keccak256(encodeType(typeName, types))
end

function encodeField(type, value, types)
    if types[type] then
        -- value is of a nested type
        return {
            type = "bytes32",
            value = hashStruct(type, value, types)
        }
    end
    -- Handle arrays
    local baseType = string.match(type, "^([%a%d]+)%[(%d*)%]$")
    if baseType then
        local arrayTypes = {}
        local arrayValues = {}
        
        -- Check if baseType is a struct type
        if types[baseType] then
            -- For arrays of structs, hash each struct individually
            for _, item in ipairs(value or {}) do
                local structHash = hashStruct(baseType, item, types)
                table.insert(arrayTypes, "bytes32")
                table.insert(arrayValues, structHash)
            end
        else
            -- For primitive arrays, process each item
            for _, item in ipairs(value or {}) do
                local itemEncoded = encodeField(baseType, item, types)
                if itemEncoded.type == "bytes32" then
                    table.insert(arrayTypes, itemEncoded.type)
                    table.insert(arrayValues, itemEncoded.value)
                else
                    table.insert(arrayTypes, 'bytes32')
                    local itemAbiEncoded = abiEncode({itemEncoded.type}, {itemEncoded.value})
                    local itemAbiEncodeBytes = Array.fromHex(itemAbiEncoded)
                    local itemEncodedBunaryStr = Array.toString(itemAbiEncodeBytes)
                    table.insert(arrayValues, keccak256(itemEncodedBunaryStr))
                end
            end
        end
        
        -- Array values are already bytes32, just encode them as an array and hash
        local apiEncoded = abiEncode(arrayTypes, arrayValues)
        local abiEncodeBytes = Array.fromHex(apiEncoded)
        local apiEncodedBunaryStr = Array.toString(abiEncodeBytes)
        return {
            type = "bytes32",
            value = keccak256(apiEncodedBunaryStr)
        }
    end
    
    -- Handle structs
    if string.match(type, "^[A-Z]") then
        return {
            type = "bytes32",
            value = keccak256(encodeData(type, value, types))
        }
    end

    -- Handle strings by hashing them to bytes32
    if type == "string" then
        return {
            type = "bytes32",
            value = keccak256(value or "")
        }
    end

    -- Handle basic types
    return {
        type = type,
        value = value
    }
end

local function getDefaultValue(typ)
    -- Handle basic types
    if typ == "uint256" or typ == "int256" then
        return 0
    elseif typ == "address" then
        return "0x0000000000000000000000000000000000000000"
    elseif typ == "bool" then
        return false
    elseif typ == "string" then
        return ""
    elseif typ == "bytes" then
        return ""
    end
    
    -- Handle fixed-size bytes
    local bytesMatch = string.match(typ, "^bytes(%d+)$")
    if bytesMatch then
        local n = tonumber(bytesMatch)
        if n then
            local size = math.floor(n)
            return string.rep("\0", size)
        end
        error("Invalid bytes size: " .. bytesMatch)
    end
    
    -- Handle arrays
    local baseType = string.match(typ, "^([%a%d]+)%[")
    if baseType then
        return {}
    end
    
    -- Handle structs (starting with uppercase)
    if string.match(typ, "^[A-Z]") then
        return {}
    end
    
    error("Unsupported type for default value: " .. typ)
end

function encodeData(typeName, data, types)
    local encTypes = {}
    local encValues = {}
    
    -- First, add the type hash
    table.insert(encTypes, "bytes32")
    table.insert(encValues, typeHash(typeName, types))
    
    -- Process fields in the exact order they appear in types
    for _, field in ipairs(types[typeName]) do
        local value = data[field.name]
        if value == nil then
            value = getDefaultValue(field.type)
        end
        local encoded = encodeField(field.type, value, types)
        table.insert(encTypes, encoded.type)
        table.insert(encValues, encoded.value)
    end
    
    -- Encode the data
    local abiEncodedData = abiEncode(encTypes, encValues, types)
    return abiEncodedData
end

function hashStruct(primaryType, data, types)
    -- First encode the data
    local encodedData = encodeData(primaryType, data, types)
    
    -- Convert hex to binary string
    local bytes = Array.fromHex(encodedData)
    local binary_string = Array.toString(bytes)
    
    -- Hash the binary string
    return keccak256(binary_string)
end

local function getSigningInput(domainSeparator, structHash)
    -- Combine domain separator and struct hash with EIP-712 prefix
    local fullInputHexString = '1901' .. domainSeparator .. structHash
    
    -- Convert hex to binary string
    local fullInputBytes = Array.fromHex(fullInputHexString)
    local fullInputBinaryStr = Array.toString(fullInputBytes)
    
    -- Hash the binary string
    return keccak256(fullInputBinaryStr)
end

local function createDomainSeparator(domain, types)
    if not types or not types.EIP712Domain then
        -- Create domain type with fields in the standard order
        local domainType = {
            {name = "name", type = "string"},
            {name = "version", type = "string"},
            {name = "chainId", type = "uint256"}
        }
        
        -- Create domain data with fields in the same order
        local domainData = {
            name = domain.name,
            version = domain.version,
            chainId = domain.chainId
        }
        
        -- Create types object with only EIP712Domain
        local types = {
            EIP712Domain = domainType
        }
        
        return hashStruct("EIP712Domain", domainData, types)
    end

    return hashStruct("EIP712Domain", domain, types)
end


  __loaded["eip712"] = {
    createDomainSeparator = createDomainSeparator,
    hashStruct = hashStruct,
    getSigningInput = getSigningInput,
    encodeType = encodeType,
    typeHash = typeHash,
    abiEncode = abiEncode
}
  return __loaded["eip712"]
end
-- End module: eip712.lua

-- Begin module: vc-validator.lua
__modules["vc-validator"] = function()
  if __loaded["vc-validator"] then return __loaded["vc-validator"] end
-- Explicitly importing secp256k1 and exposing recover_public_key, which is a global var in our custom AO module.

local recover_public_key = recover_public_key

local json = require("json")
local Array = require(".crypto.util.array")
local crypto = require(".crypto.init")

local eip712 = __modules["eip712"]()

local function strip_hex_prefix(hex_str)
  if hex_str:sub(1, 2) == "0x" then
    return hex_str:sub(3)
  end
  return hex_str
end

local function pubkey_to_eth_address(pubkey_hex)
  if #pubkey_hex ~= 130 or pubkey_hex:sub(1, 2) ~= '04' then
    error('toEthereumAddress: Expecting an uncompressed public key')
  end
  local pubkey_hex_clean = pubkey_hex:sub(3) -- dropping the leading '04' indicating an uncompressed public key format
  local pubkey_binary_bytes = Array.fromHex(pubkey_hex_clean)
  local pubkey_binary_str = Array.toString(pubkey_binary_bytes)
  local keccak_hash = crypto.digest.keccak256(pubkey_binary_str).asHex()
  return '0x'..string.sub(keccak_hash, -40, -1); -- last 40 hex chars, aka 20 bytes
end

local function decode_signature(signature)
  local sanitized_sig = strip_hex_prefix(signature)

  if #sanitized_sig ~= 130 then
    error("Invalid signature length: expected 130 hex chars (65 bytes)")
  end

  return sanitized_sig
end

local function string_split(inputstr, sep)
  if sep == nil then
    sep = "%s"
  end
  local t = {}
  for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
    table.insert(t, str)
  end
  return t
end

local function get_authority(issuer)
  local eth_address = nil
  if (issuer) then
    local parts = string_split(issuer, ':')
    -- eg. 'did:pkh:eip155:1:0x1e8564A52fc67A68fEe78Fc6422F19c07cFae198'
    if (parts[1] == 'did' and parts[2] == 'pkh' and parts[3] == 'eip155' and parts[4] == '1') then
      eth_address = parts[5]
    else
      error('Only supporting did:pkh issuers')
    end
    return string.lower(eth_address or '')
  end
  error('No issuer found')
end

local function vc_validate(vc)
  local vc_json = json.decode(vc)
  local owner_eth_address = get_authority(vc_json.issuer.id)
  local proof = vc_json.proof
  local proofValue = nil
  local signature_hex = nil
  if proof.type == 'EthereumEip712Signature2021' then
    proofValue = proof.proofValue
    signature_hex = decode_signature(proofValue)
  else
    error('Only supporting EthereumEip712Signature2021 proof type')
  end

  local eip712data = vc_json.proof.eip712
  local domain = eip712data.domain
  local types = eip712data.types
  local primaryType = eip712data.primaryType
  local domainSeparator = eip712.createDomainSeparator(domain)

  local message = Array.copy(vc_json)
  local proof_copy = Array.copy(vc_json.proof)
  proof_copy.proofValue = nil
  proof_copy.eip712 = nil
  proof_copy.eip712Domain = nil
  message.proof = proof_copy

  local structHash = eip712.hashStruct(primaryType, message, types)
  local signingInput = eip712.getSigningInput(domainSeparator, structHash)
  -- print('Signing Input:', signingInput)

  -- Recover public key and verify
  local pubkey_hex = recover_public_key(signature_hex, signingInput)
  local eth_address = pubkey_to_eth_address(pubkey_hex)
  local success = eth_address == owner_eth_address

  -- print('Recovered ETH Address:', eth_address)
  -- print('Validation Result:', success)
  -- print('===================')

  return success, vc_json, owner_eth_address
end


  __loaded["vc-validator"] = {
  validate = vc_validate,
}
  return __loaded["vc-validator"]
end
-- End module: vc-validator.lua

-- Begin module: variables/validation.lua
__modules["variables/validation"] = function()
  if __loaded["variables/validation"] then return __loaded["variables/validation"] end
-- Shared validation module for both InputVerifier and VariableManager
local ValidationModule = {}

-- Core validation function that can be used for both variables and input fields
-- Returns success (boolean) and error message (string or nil)
function ValidationModule.validateValue(value, validation, fieldName)
    -- Skip validation if validation rules not provided
    if not validation then
        return true, nil
    end

    -- Check required field
    if validation.required and (value == nil or value == "") then
        return false, string.format("%s is required", fieldName)
    end

    -- Skip remaining validation if value is nil and not required
    if value == nil then
        return true, nil
    end

    -- Type validation is handled by the caller, as the type checks differ
    -- between variables and input fields

    -- String validations
    if type(value) == "string" then
        -- Min length
        if validation.minLength and #value < validation.minLength then
            return false, string.format("%s must be at least %d characters", fieldName, validation.minLength)
        end
        
        -- Max length
        if validation.maxLength and #value > validation.maxLength then
            return false, string.format("%s must be at most %d characters", fieldName, validation.maxLength)
        end
        
        -- Pattern
        if validation.pattern then
            local pattern = validation.pattern:gsub("\\/", "/")
            if not string.match(value, pattern) then
                return false, string.format("%s: %s", fieldName, validation.message or "Invalid format")
            end
        end
    end
    
    -- Number validations
    if type(value) == "number" then
        -- Min value
        if validation.min and value < validation.min then
            return false, string.format("%s must be at least %s", fieldName, tostring(validation.min))
        end
        
        -- Max value
        if validation.max and value > validation.max then
            return false, string.format("%s must be at most %s", fieldName, tostring(validation.max))
        end
    end
    
    return true, nil
end


  __loaded["variables/validation"] = ValidationModule
  return __loaded["variables/validation"]
end
-- End module: variables/validation.lua

-- Begin module: variables/variable_manager.lua
__modules["variables/variable_manager"] = function()
  if __loaded["variables/variable_manager"] then return __loaded["variables/variable_manager"] end
local VcValidator = __modules["vc-validator"]()
local ValidationModule = __modules["variables/validation"]()
local VariableManager = {}

function VariableManager.new(variables)
    local self = {
        variables = {}
    }
    
    for id, var in pairs(variables) do
        self.variables[id] = {
            value = var.value,
            type = var.type,
            name = var.name,
            description = var.description,
            validation = var.validation,
            txMetadata = var.txMetadata,
            get = function(self)
                return self.value
            end,
            set = function(self, newValue)
                if self.validation then
                    -- Use shared validation module for common validations
                    local isValid, errorMsg = ValidationModule.validateValue(newValue, self.validation, self.name or id)
                    if not isValid then
                        error(string.format("Validation failed for variable '%s': %s (value: %s, type: %s)", 
                            self.name or id, errorMsg, tostring(newValue), type(newValue)))
                    end
                end
                self.value = newValue
            end
        }
    end

    setmetatable(self, { __index = VariableManager })
    return self
end

function VariableManager:isVariable(name)
    return self.variables[name] ~= nil
end

function VariableManager:getVariable(name)
    local var = self.variables[name]
    if not var then
        error(string.format("Variable not found: %s", name))
    end
    return var:get()
end

function VariableManager:setVariable(name, value)
    local var = self.variables[name]
    if not var then
        error(string.format("Variable not found: %s", name))
    end
    
    local success, err = pcall(function() var:set(value) end)
    if not success then
        error(string.format("Failed to set variable '%s' (type: %s): %s", 
            name, var.type, err))
    end
end

function VariableManager:getAllVariables()
    local result = {}
    for name, var in pairs(self.variables) do
        result[name] = {
            value = var:get(),
            type = var.type,
            name = var.name,
            description = var.description
        }
    end
    return result
end

-- Given a string input, resolve it as a variable reference 
-- (e.g. ${variables.partyAEthAddress.value} will return the nested property value)
-- Otherwise, return nil
function VariableManager:tryResolveExactStringAsVariableObject(possibleVariableReferenceString)
    if type(possibleVariableReferenceString) ~= "string" then
        return nil
    end

    local trimmed = possibleVariableReferenceString:match("^%s*(.-)%s*$")
    
    -- Check if the string has ${variables.x} format
    local varPath = trimmed:match("^%${([^}]+)}$")
    if not varPath or not varPath:match("^variables%.") then
        return nil
    end

    -- Remove the "variables." prefix and split the remaining path
    local path = varPath:sub(10) -- Remove "variables."
    local parts = {}
    for part in path:gmatch("[^%.]+") do
        table.insert(parts, part)
    end

    if #parts == 0 then
        return nil
    end

    -- Get the base variable definition
    local varDef = self.variables[parts[1]]
    if not varDef then
        return nil
    end

    -- Start with the variable definition object itself
    local current = varDef
    
    -- Handle different property paths
    if #parts > 1 then
        -- First property access (parts[2])
        if parts[2] == "value" then
            current = current:get()
        else
            current = current[parts[2]]
        end
        
        if current == nil then
            return nil
        end
        
        -- Traverse any remaining nested properties (from index 3 onward)
        for i = 3, #parts do
            if type(current) ~= "table" then
                return nil
            end
            current = current[parts[i]]
            if current == nil then
                return nil
            end
        end
    end

    return current
end


  __loaded["variables/variable_manager"] = VariableManager
  return __loaded["variables/variable_manager"]
end
-- End module: variables/variable_manager.lua

-- Begin module: mock-oracle.lua
__modules["mock-oracle"] = function()
  if __loaded["mock-oracle"] then return __loaded["mock-oracle"] end
-- MockOracle: A class that simulates an oracle by storing and retrieving data
-- associated with transaction hashes
local json = require("json")

local function loadOracleData()
    local file = io.open("./mock-oracle-data.json", "r")
    if not file then
        error("Could not open agreement document file")
    end
    local content = file:read("*all")
    file:close()
    return content
end


local MockOracle = {}
MockOracle.__index = MockOracle

-- Create a new MockOracle instance
function MockOracle.new()
    local self = setmetatable({}, MockOracle)
    local data = loadOracleData()
    self.data = json.decode(data)  -- Dictionary to store transaction hash -> data mappings
    return self
end

-- Store data for a transaction hash
-- @param txHash: The transaction hash to use as a key
-- @param blobData: The data to store for this transaction
function MockOracle:store(txHash, blobData)
    self.data[txHash] = blobData
end

-- Retrieve data for a transaction hash
-- @param txHash: The transaction hash to look up
-- @return: The stored data if it exists, nil otherwise
function MockOracle:retrieve(txHash)
    return self.data[txHash]
end

-- Check if data exists for a transaction hash
-- @param txHash: The transaction hash to check
-- @return: true if data exists, false otherwise
function MockOracle:exists(txHash)
    return self.data[txHash] ~= nil
end

-- Remove data for a transaction hash
-- @param txHash: The transaction hash to remove
function MockOracle:remove(txHash)
    self.data[txHash] = nil
end

-- Get all stored transaction hashes
-- @return: An array of all transaction hashes in the oracle
function MockOracle:getAllTxHashes()
    local hashes = {}
    for hash, _ in pairs(self.data) do
        table.insert(hashes, hash)
    end
    return hashes
end


  __loaded["mock-oracle"] = MockOracle
  return __loaded["mock-oracle"]
end
-- End module: mock-oracle.lua

-- Begin module: utils/table_utils.lua
__modules["utils/table_utils"] = function()
  if __loaded["utils/table_utils"] then return __loaded["utils/table_utils"] end
-- Table utility functions

-- Helper function to perform deep comparison of two values
local function deepCompare(a, b)
    -- Handle nil cases
    if a == nil and b == nil then return true end
    if a == nil or b == nil then return false end
    -- Handle different types
    if type(a) ~= type(b) then return false end
    -- Handle non-table types
    if type(a) ~= "table" then
        return a == b
    end
    -- Handle arrays (tables with numeric keys)
    if #a > 0 or #b > 0 then
        if #a ~= #b then return false end
        for i = 1, #a do
            if not deepCompare(a[i], b[i]) then
                return false
            end
        end
        return true
    end
    -- Handle objects (tables with string keys)
    local aKeys = {}
    local bKeys = {}
    -- Collect keys
    for k in pairs(a) do
        aKeys[k] = true
    end
    for k in pairs(b) do
        bKeys[k] = true
    end
    -- Check if they have the same keys
    for k in pairs(aKeys) do
        if not bKeys[k] then return false end
    end
    for k in pairs(bKeys) do
        if not aKeys[k] then return false end
    end
    -- Compare values for each key
    for k in pairs(a) do
        if not deepCompare(a[k], b[k]) then
            return false
        end
    end

    return true
end

-- Helper function to replace variable references with their values
local function replaceVariableReferences(obj, variablesTable)
    if type(obj) ~= "table" then
        if type(obj) == "string" then
            -- Look for ${variableName} pattern
            return obj:gsub("%${variables%.([^%.]+)%.value}", function(varName)
                local var = variablesTable[varName]
                if var then
                    return tostring(var:get())
                end
                return "${" .. varName .. "}" -- Keep original if variable not found
            end)
        end
        return obj
    end
    -- Handle arrays
    if #obj > 0 then
        local result = {}
        for i, v in ipairs(obj) do
            result[i] = replaceVariableReferences(v, variablesTable)
        end
        return result
    end
    -- Handle objects
    local result = {}
    for k, v in pairs(obj) do
        result[k] = replaceVariableReferences(v, variablesTable)
    end
    return result
end

-- Helper function to replace contract references with their actual table values
local function replaceContractReferences(obj, contractsTable)
    if type(obj) ~= "table" then
        if type(obj) == "string" then
            -- Only replace if the entire string matches the pattern
            local contractName = obj:match("^%${contracts%.([%w_]+)}$")
            if contractName then
                local contract = contractsTable[contractName]
                if contract then
                    return contract
                end
                return "${contracts." .. contractName .. "}" -- Keep original if contract not found
            end
        end
        return obj
    end
    -- Handle arrays
    if #obj > 0 then
        local result = {}
        for i, v in ipairs(obj) do
            result[i] = replaceContractReferences(v, contractsTable)
        end
        return result
    end
    -- Handle objects
    local result = {}
    for k, v in pairs(obj) do
        result[k] = replaceContractReferences(v, contractsTable)
    end
    return result
end

-- Helper function to print a table in a readable format
local function printTable(t, indent, visited)
    indent = indent or 0
    visited = visited or {}
    
    -- Handle non-table values
    if type(t) ~= "table" then
        print(string.rep("  ", indent) .. tostring(t))
        return
    end
    
    -- Handle already visited tables to prevent infinite recursion
    if visited[t] then
        print(string.rep("  ", indent) .. "[circular reference]")
        return
    end
    visited[t] = true
    
    -- Handle empty table
    if next(t) == nil then
        print(string.rep("  ", indent) .. "{}")
        return
    end
    
    -- Handle arrays (tables with numeric keys)
    if #t > 0 then
        print(string.rep("  ", indent) .. "[")
        for i, v in ipairs(t) do
            print(string.rep("  ", indent + 1) .. tostring(i) .. ":")
            printTable(v, indent + 2, visited)
        end
        print(string.rep("  ", indent) .. "]")
        return
    end
    
    -- Handle objects (tables with string keys)
    print(string.rep("  ", indent) .. "{")
    for k, v in pairs(t) do
        print(string.rep("  ", indent + 1) .. tostring(k) .. ":")
        printTable(v, indent + 2, visited)
    end
    print(string.rep("  ", indent) .. "}")
end


  __loaded["utils/table_utils"] = {
    deepCompare = deepCompare,
    replaceVariableReferences = replaceVariableReferences,
    replaceContractReferences = replaceContractReferences,
    printTable = printTable
}
  return __loaded["utils/table_utils"]
end
-- End module: utils/table_utils.lua

-- Begin module: verifiers/evm_transaction_input_verifier.lua
__modules["verifiers/evm_transaction_input_verifier"] = function()
  if __loaded["verifiers/evm_transaction_input_verifier"] then return __loaded["verifiers/evm_transaction_input_verifier"] end

local crypto = require(".crypto.init")
local json = require("json")
local base64 = require(".base64")
-- local MockOracle = __modules["mock-oracle"]()  -- Import the MockOracle module
local replaceVariableReferences = __modules["utils/table_utils"]().replaceVariableReferences
local replaceContractReferences = __modules["utils/table_utils"]().replaceContractReferences

-- Helper functions
-- EIP-712 specific functions
local function keccak256(input)
    return crypto.digest.keccak256(input).asHex()
end

local function removeHexPrefix(val)
    if val[1] % 2 == 1 then
        -- In Lua, we can use table.move for slicing or manually recreate the array
        local result = {}
        for i = 2, #val do
        result[i-1] = val[i]
        end
        return result
    else
        -- Create a new table without the first two elements
        local result = {}
        for i = 3, #val do
        result[i-2] = val[i]
        end
        return result
    end
end

local function rlpEncode(value)
    -- RLP encoding implementation
    -- For single bytes < 128, the byte itself is its own RLP encoding
    -- For short strings (0-55 bytes), RLP is [0x80+len(data)] + data
    -- For long strings, RLP is [0xb7+len(len(data))] + len(data) + data
    -- For lists, similar rules apply with different offset values
    
    -- Handle integers
    if type(value) == "number" then
        -- Convert to hex string without leading zeros
        local hex = string.format("%x", value)
        if #hex % 2 ~= 0 then hex = "0" .. hex end
        
        -- Convert hex to bytes (as numbers in a table)
        local bytes = {}
        for i = 1, #hex, 2 do
            local byte = tonumber(hex:sub(i, i+1), 16)
            table.insert(bytes, byte)
        end
        
        -- If value is 0, return [0x80] (empty string)
        if value == 0 then
            return {0x80}
        -- Single byte < 128, return as is
        elseif #bytes == 1 and bytes[1] < 128 then
            return bytes
        -- Short string
        elseif #bytes <= 55 then
            local result = {0x80 + #bytes}
            for i = 1, #bytes do
                table.insert(result, bytes[i])
            end
            return result
        -- Long string
        else
            local lengthBytes = {}
            local lengthHex = string.format("%x", #bytes)
            if #lengthHex % 2 ~= 0 then lengthHex = "0" .. lengthHex end
            
            for i = 1, #lengthHex, 2 do
                local byte = tonumber(lengthHex:sub(i, i+1), 16)
                table.insert(lengthBytes, byte)
            end
            
            local result = {0xb7 + #lengthBytes}
            for i = 1, #lengthBytes do
                table.insert(result, lengthBytes[i])
            end
            for i = 1, #bytes do
                table.insert(result, bytes[i])
            end
            return result
        end
    end
    
    -- Handle other types (strings, tables, etc.) would go here
    -- This implementation focuses on encoding integers which is what's needed for transaction indices
end

local function rlpDecode(rlpBytes)
    -- Handle empty input
    if #rlpBytes == 0 then
        return nil
    end
    
    local firstByte = rlpBytes[1]
    local result = {}
    local i = 1
    
    -- Case 1: Single byte < 0x80 (128) represents itself
    if firstByte < 0x80 then
        return {rlpBytes[1]} -- Return as a single-element byte array
    
    -- Case 2: Short string (0-55 bytes)
    elseif firstByte <= 0xb7 then
        local length = firstByte - 0x80
        
        -- Empty string case
        if length == 0 then
            return {} -- Return empty array
        end
        
        -- Check if we have enough bytes
        if #rlpBytes < length + 1 then
            error("Invalid RLP: not enough bytes for short string")
        end
        
        -- Extract the bytes directly
        local result = {}
        for i = 2, length + 1 do
            table.insert(result, rlpBytes[i])
        end
        
        return result
    
    -- Case 3: Long string (>55 bytes)
    elseif firstByte <= 0xbf then
        local lengthOfLength = firstByte - 0xb7
        
        -- Check if we have enough bytes for the length
        if #rlpBytes < lengthOfLength + 1 then
            error("Invalid RLP: not enough bytes for length prefix")
        end
        
        -- Extract the length bytes
        local lengthHex = ""
        for i = 2, lengthOfLength + 1 do
            lengthHex = lengthHex .. string.format("%02x", rlpBytes[i])
        end
        
        local length = tonumber(lengthHex, 16)
        
        -- Check if we have enough bytes for the value
        if #rlpBytes < lengthOfLength + 1 + length then
            error("Invalid RLP: not enough bytes for long string")
        end
        
        -- Extract the bytes directly
        local result = {}
        for i = lengthOfLength + 2, lengthOfLength + 1 + length do
            table.insert(result, rlpBytes[i])
        end
        
        return result
    
    -- Case 4: Lists
    elseif firstByte <= 0xf7 then
        -- Short list (0-55 bytes)
        local length = firstByte - 0xc0
        
        -- Empty list case
        if length == 0 then
            return {} -- Return empty array
        end
        
        -- Check if we have enough bytes
        if #rlpBytes < length + 1 then
            error("Invalid RLP: not enough bytes for short list")
        end
        
        -- Extract the list items
        local listBytes = {}
        for i = 2, length + 1 do
            table.insert(listBytes, rlpBytes[i])
        end
        
        -- Decode the list items
        local result = {}
        local offset = 1
        while offset <= #listBytes do
            -- Create a sub-array of bytes starting from the current offset
            local subBytes = {}
            for i = offset, #listBytes do
                table.insert(subBytes, listBytes[i])
            end
            
            -- Recursively decode the item
            local item = rlpDecode(subBytes)
            table.insert(result, item)
            
            -- Calculate the length of the encoded item to update the offset
            local itemLength = 0
            local itemFirstByte = listBytes[offset]
            
            if itemFirstByte < 0x80 then
                -- Single byte
                itemLength = 1
            elseif itemFirstByte <= 0xb7 then
                -- Short string
                itemLength = (itemFirstByte - 0x80) + 1
            elseif itemFirstByte <= 0xbf then
                -- Long string
                local lengthOfLength = itemFirstByte - 0xb7
                local lengthHex = ""
                for i = offset + 1, offset + lengthOfLength do
                    lengthHex = lengthHex .. string.format("%02x", listBytes[i])
                end
                local dataLength = tonumber(lengthHex, 16)
                itemLength = 1 + lengthOfLength + dataLength
            elseif itemFirstByte <= 0xf7 then
                -- Short list
                itemLength = (itemFirstByte - 0xc0) + 1
            else
                -- Long list
                local lengthOfLength = itemFirstByte - 0xf7
                local lengthHex = ""
                for i = offset + 1, offset + lengthOfLength do
                    lengthHex = lengthHex .. string.format("%02x", listBytes[i])
                end
                local dataLength = tonumber(lengthHex, 16)
                itemLength = 1 + lengthOfLength + dataLength
            end
            
            offset = offset + itemLength
        end
        
        return result
    
    elseif firstByte <= 0xff then
        -- Long list (>55 bytes)
        local lengthOfLength = firstByte - 0xf7
        
        -- Check if we have enough bytes for the length
        if #rlpBytes < lengthOfLength + 1 then
            error("Invalid RLP: not enough bytes for length prefix in long list")
        end
        
        -- Extract the length bytes
        local lengthHex = ""
        for i = 2, lengthOfLength + 1 do
            lengthHex = lengthHex .. string.format("%02x", rlpBytes[i])
        end
        
        local length = tonumber(lengthHex, 16)
        
        -- Check if we have enough bytes for the list
        if #rlpBytes < lengthOfLength + 1 + length then
            error("Invalid RLP: not enough bytes for long list")
        end
        
        -- Extract the list bytes
        local listBytes = {}
        for i = lengthOfLength + 2, lengthOfLength + 1 + length do
            table.insert(listBytes, rlpBytes[i])
        end
        
        -- Decode the list items
        local result = {}
        local offset = 1
        while offset <= #listBytes do
            -- Create a sub-array of bytes starting from the current offset
            local subBytes = {}
            for i = offset, #listBytes do
                table.insert(subBytes, listBytes[i])
            end
            
            -- Recursively decode the item
            local item = rlpDecode(subBytes)
            table.insert(result, item)
            
            -- Calculate the length of the encoded item to update the offset
            local itemLength = 0
            local itemFirstByte = listBytes[offset]
            
            if itemFirstByte < 0x80 then
                -- Single byte
                itemLength = 1
            elseif itemFirstByte <= 0xb7 then
                -- Short string
                itemLength = (itemFirstByte - 0x80) + 1
            elseif itemFirstByte <= 0xbf then
                -- Long string
                local lengthOfLength = itemFirstByte - 0xb7
                local lengthHex = ""
                for i = offset + 1, offset + lengthOfLength do
                    lengthHex = lengthHex .. string.format("%02x", listBytes[i])
                end
                local dataLength = tonumber(lengthHex, 16)
                itemLength = 1 + lengthOfLength + dataLength
            elseif itemFirstByte <= 0xf7 then
                -- Short list
                itemLength = (itemFirstByte - 0xc0) + 1
            else
                -- Long list
                local lengthOfLength = itemFirstByte - 0xf7
                local lengthHex = ""
                for i = offset + 1, offset + lengthOfLength do
                    lengthHex = lengthHex .. string.format("%02x", listBytes[i])
                end
                local dataLength = tonumber(lengthHex, 16)
                itemLength = 1 + lengthOfLength + dataLength
            end
            
            offset = offset + itemLength
        end
        
        return result
    else
        error("Invalid RLP encoding")
    end
end

local function bytesToString(bytes)
    local chars = {}
    for i = 1, #bytes do
        chars[i] = string.char(bytes[i])
    end
    return table.concat(chars)
end

local function bytesToHex(bytes)
    local hex = ""
    for i = 1, #bytes do
        -- Convert each byte to its hex representation
        -- %02x formats as 2-digit hex with leading zeros
        hex = hex .. string.format("%02x", bytes[i])
    end
    return hex
end

local function hexToBytes(hexString)
    local bytes = {}
    
    -- Remove any non-hex characters (like spaces or 0x prefix)
    hexString = hexString:gsub("[^0-9A-Fa-f]", "")
    
    -- Ensure we have an even number of hex digits
    if #hexString % 2 ~= 0 then
        hexString = "0" .. hexString
    end
    
    -- Convert each pair of hex digits to a byte
    for i = 1, #hexString, 2 do
        local byteString = hexString:sub(i, i + 1)
        local byte = tonumber(byteString, 16)
        table.insert(bytes, byte)
    end
    
    return bytes
end

local function bytesToNibbles(key)
    local nibbles = {}
    
    for i = 1, #key do
        local byte = key[i]
        -- Get the high nibble (first 4 bits)
        local highNibble = math.floor(byte / 16)
        -- Get the low nibble (last 4 bits)
        local lowNibble = byte % 16
        
        -- Store both nibbles
        local q = (i - 1) * 2 + 1
        nibbles[q] = highNibble
        nibbles[q + 1] = lowNibble
    end
    
    return nibbles
end

-- Add this helper function to compare byte arrays
local function equalsBytes(bytes1, bytes2)
    if #bytes1 ~= #bytes2 then
        return false
    end
    
    for i = 1, #bytes1 do
        if bytes1[i] ~= bytes2[i] then
            return false
        end
    end
    
    return true
end

local function isTerminator(key)
    return key[1] > 1
end

local ExtensionNode = {}
ExtensionNode.__index = ExtensionNode

-- Constructor
function ExtensionNode.new(nibbles, value)
    local self = setmetatable({}, ExtensionNode)
    self.nibbles = nibbles
    self.value = value
    return self
end

-- Method to check if an object is an instance of MyClass
function ExtensionNode.isInstance(obj)
    return type(obj) == "table" and getmetatable(obj) == ExtensionNode
end

local LeafNode = {}
LeafNode.__index = LeafNode

-- Constructor
function LeafNode.new(nibbles, value)
    local self = setmetatable({}, LeafNode)
    self.nibbles = nibbles
    self.value = value
    return self
end

-- Method to check if an object is an instance of MyClass
function LeafNode.isInstance(obj)
    return type(obj) == "table" and getmetatable(obj) == LeafNode
end

local BranchNode = {}
BranchNode.__index = BranchNode

-- Constructor
function BranchNode.new(array)
    local self = setmetatable({}, BranchNode)
    self.branches = {table.unpack(array, 1, 16)}
    self.value = array[17]
    return self
end

-- Method to check if an object is an instance of MyClass
function BranchNode.isInstance(obj)
    return type(obj) == "table" and getmetatable(obj) == BranchNode
end


Trie = {}
Trie.__index = Trie

-- Constructor function
function Trie.new(root)
    local self = setmetatable({}, Trie)
    if root ~= nil then
        self.root = root
    end
    self.db = {}
    return self
end

function Trie:updateFromProof(proof)
    local opStack = {}
  
    for i, nodeValue in ipairs(proof) do
        local key = hexToBytes(keccak256(bytesToString(nodeValue))) 
        table.insert(opStack, {key = key, value = nodeValue})
    end

    -- check if the root matches
    if opStack[1] ~= nil then
        if not equalsBytes(self.root, opStack[1].key) then
            error('The provided proof does not have the expected trie root')
        else 
            -- print('root is good')
        end
    end

    -- insert the proof into the db
    for i, op in ipairs(opStack) do
        self.db[bytesToHex(op.key)] = op.value
        -- table.insert(self.db, {key = bytesToHex(op.key), value = op.value})
    end
end

function Trie:lookupNode(node)
    -- if (isRawNode(node)) {
    --     const decoded = decodeRawNode(node)
    --     return decoded
    -- }
    local key = bytesToHex(node)
    local value = self.db[key]

    if value == nil then
        -- error('Missing node in DB')
        return;
    end

    local raw = rlpDecode(value)
    if raw == nil then
        error('Failed to decode node')
    end
    if #raw == 17 then
        return BranchNode.new(raw)
    elseif #raw == 2 then
        local nibbles = bytesToNibbles(raw[1])
        if isTerminator(nibbles) then
            return LeafNode.new(removeHexPrefix(nibbles), raw[2])
        end
        return ExtensionNode.new(removeHexPrefix(nibbles), raw[2])
    else
        error("Invalid node")
    end    
end

-- function Trie:walkTrie()
--     local node = self:lookupNode(self.root)
--     self:processNode(self.root, node, {})
-- end

function Trie:findPath(key)
    local targetKey = bytesToNibbles(key)
    local keyLen = #targetKey
    local stack = {}
    local progress = 0
    local result = nil

    -- Helper function to process nodes during trie traversal
    local function processNode(nodeRef, node, keyProgress)
        if node == nil then
            return
        end

        stack[progress + 1] = node

        if BranchNode.isInstance(node) then
            if progress == keyLen then
                -- Found exact match at branch node
                result = {
                    node = node,
                    remaining = {},
                    stack = stack
                }
            else
                -- Get branch index from target key
                local branchIndex = targetKey[progress + 1]
                local branchNode = node.branches[branchIndex + 1]

                if branchNode == nil then
                    -- No matching branch found
                    result = {
                        node = nil,
                        remaining = {},  -- Create slice of targetKey from progress
                        stack = stack
                    }
                    for i = progress + 1, keyLen do
                        table.insert(result.remaining, targetKey[i])
                    end
                else
                    progress = progress + 1
                    -- Continue walking down this branch
                    local nextNode = self:lookupNode(branchNode)
                    processNode(branchNode, nextNode, keyProgress + 1)
                end
            end

        elseif LeafNode.isInstance(node) then
            local nodeKey = node.nibbles
            local _progress = progress

            -- Check if remaining key is longer than leaf node key
            if keyLen - progress > #nodeKey then
                result = {
                    node = nil,
                    remaining = {},
                    stack = stack
                }
                -- Add remaining key to result
                for i = _progress + 1, keyLen do
                    table.insert(result.remaining, targetKey[i])
                end
                return
            end

            -- Compare each nibble
            for i = 1, #nodeKey do
                if nodeKey[i] ~= targetKey[progress + i] then
                    result = {
                        node = nil,
                        remaining = {},
                        stack = stack
                    }
                    -- Add remaining key to result
                    for j = _progress + 1, keyLen do
                        table.insert(result.remaining, targetKey[j])
                    end
                    return
                end
            end
            progress = progress + #nodeKey
            result = {
                node = node,
                remaining = {},
                stack = stack
            }

        elseif ExtensionNode.isInstance(node) then
            local nodeKey = node.nibbles
            local _progress = progress

            -- Compare extension node key with target key
            for i = 1, #nodeKey do
                if nodeKey[i] ~= targetKey[progress + i] then
                    result = {
                        node = nil,
                        remaining = {},
                        stack = stack
                    }
                    -- Add remaining key to result
                    for j = _progress + 1, keyLen do
                        table.insert(result.remaining, targetKey[j])
                    end
                    return
                end
            end
            progress = progress + #nodeKey

            -- Continue walking with the extension node's value
            local nextNode = self:lookupNode(node.value)
            processNode(node.value, nextNode, keyProgress + #nodeKey)
        end
    end

    -- Start walking from root
    local node = self:lookupNode(self.root)
    processNode(self.root, node, 0)

    -- If no result was found, return empty result
    if result == nil then
        result = {
            node = nil,
            remaining = {},
            stack = stack
        }
    end

    -- Filter out nil values from stack
    local filteredStack = {}
    for i = 1, #stack do
        if stack[i] ~= nil then
            table.insert(filteredStack, stack[i])
        end
    end
    result.stack = filteredStack

    return result
end

function Trie:get(key)
    local result =self:findPath(key)
    -- const { node, remaining } = self.findPath(key)
    local value = nil
    if result.node ~= nil and #result.remaining == 0 then
        value = result.node.value
    end
    return value
end

local function verifyMerkleProof(key, root, proof, value)
    -- 2. convert blocks transactions root to buffer
    local rootBytes = {}
    -- Remove '0x' prefix if present
    if root:sub(1, 2) == "0x" then
        root = root:sub(3)
    end
    
    -- Convert hex string to byte array
    for i = 1, #root, 2 do
        local byte = tonumber(root:sub(i, i+1), 16)
        table.insert(rootBytes, byte)
    end
    
    -- 3. verify the proof by checking the transaction root and getting the value at the transaction index
    local trie = Trie.new(rootBytes)
    trie:updateFromProof(proof)

    -- 4. compare the value to the expected value and return result
    local proofValue = trie:get(key)
    return equalsBytes(value, proofValue)
end

local function verifyProof(txHash, txIndex, txRoot, txProof, txValue, receiptRoot, receiptProof, receiptValue)
    -- 1. RLP encode transaction index
    local key = rlpEncode(tonumber(txIndex))
    return verifyMerkleProof(key, txRoot, txProof, txValue) and verifyMerkleProof(key, receiptRoot, receiptProof, receiptValue)
end

-- Export the verifier function
local function verifyEVMTransaction(input, value, dfsm)
    local base64Proof = value.proof;
    local txHash = value.value;
    value = json.decode(base64.decode(base64Proof))

    if (value.TxHash ~= txHash) then
        return false
    end

    local isValid = verifyProof(value.TxHash, value.TxIndex, value.TxRoot, value.TxProof, value.TxEncodedValue, value.ReceiptRoot, value.ReceiptProof, value.ReceiptEncodedValue)

    if not isValid then
        return false
    end

    local variables = dfsm.variables
    local contracts = dfsm.contracts

    local processedRequiredInput = replaceVariableReferences(input.txMetadata, variables.variables)
    processedRequiredInput = replaceContractReferences(processedRequiredInput, contracts.contracts)
    if processedRequiredInput.transactionType == "nativeTransfer" then
        if string.lower(value.TxRaw.from) ~= string.lower(processedRequiredInput.from) 
            or string.lower(value.TxRaw.to) ~= string.lower(processedRequiredInput.to) 
            or value.TxRaw.value ~= processedRequiredInput.value
            or value.TxRaw.chainId ~= processedRequiredInput.chainId then
            return false
        end
        return true
    elseif processedRequiredInput.transactionType == "contractCall" then
        local contract = processedRequiredInput.contractReference
        local decodedTx = contract:decode(value.TxRaw.data)
        if (decodedTx.function_name ~= processedRequiredInput.method) then
            return false
        end

        for _, param in ipairs(decodedTx.parameters) do
            if (string.lower(param.value) ~= string.lower(processedRequiredInput.params[param.name])) then
                return false
            end
        end

        if processedRequiredInput.signer ~= nil then
            local signer = processedRequiredInput.signer
            local signerAddress = value.TxRaw.from
            if string.lower(signerAddress) ~= string.lower(signer) then
                return false
            end
        end

        return true
    else
    end

    return true
end

-- Return the verifier function

  __loaded["verifiers/evm_transaction_input_verifier"] = verifyEVMTransaction
  return __loaded["verifiers/evm_transaction_input_verifier"]
end
-- End module: verifiers/evm_transaction_input_verifier.lua

-- Begin module: verifiers/input_verifier.lua
__modules["verifiers/input_verifier"] = function()
  if __loaded["verifiers/input_verifier"] then return __loaded["verifiers/input_verifier"] end
local json = require("json")
local crypto = require(".crypto")
local VcValidator = __modules["vc-validator"]()
local FieldValidator = __modules["variables/validation"]()
local verifyEVMTransactionInputVerifier = __modules["verifiers/evm_transaction_input_verifier"]()

local ETHEREUM_ADDRESS_REGEX = "^0x(%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x)$"

-- Helper function to validate Ethereum address checksum
local function validateEthAddressChecksum(address)
    -- Remove 0x prefix and convert to lowercase
    local addr = string.lower(string.sub(address, 3))
    
    -- Calculate keccak256 hash of the lowercase address
    local hash = crypto.digest.keccak256(addr).asHex()
    
    -- Check each character
    for i = 1, #addr do
        local c = string.sub(addr, i, i)
        local h = string.sub(hash, i, i)
        local hnum = tonumber(h, 16)
        
        -- If the hash digit is 8 or higher, the address character should be uppercase
        if hnum >= 8 then
            if string.sub(address, i + 2, i + 2) ~= string.upper(c) then
                return false
            end
        else
            if string.sub(address, i + 2, i + 2) ~= c then
                return false
            end
        end
    end
    
    return true
end

-- Shared validation module
local ValidationUtils = {}

-- Helper function for address equality
ValidationUtils.ethAddressEqual = function (address1, address2)
    return string.lower(address1) == string.lower(address2)
end

-- Variable validation function
ValidationUtils.validateVariable = function(varDef, value, dfsm)
    if varDef == nil then
        return false, "Variable definition is missing"
    end

    -- Validate type first (specific to InputVerifier)
    if varDef.type == "string" and type(value) ~= "string" then
        return false, string.format("Variable %s must be a string", varDef.name or varDef.id)
    elseif varDef.type == "address" then
        -- Basic format validation
        if not string.match(value, ETHEREUM_ADDRESS_REGEX) then
            return false, string.format("Variable %s must be a valid Ethereum address format", varDef.name or varDef.id)
        end
        
        -- Checksum validation
        if not validateEthAddressChecksum(value) then
            return false, string.format("Variable %s must be a valid Ethereum address with correct checksum", varDef.name or varDef.id)
        end
        
        print("Address validation passed")
    elseif varDef.type == "number" and type(value) ~= "number" then
        return false, string.format("Variable %s must be a number", varDef.name or varDef.id)
    elseif varDef.type == "txHash" then
        if not value.proof then
            return false, string.format("Variable %s must include a proof", varDef.name or varDef.id)
        end

        if not verifyEVMTransactionInputVerifier(varDef, value, dfsm) then
            return false, string.format("Proof provided for variable %s is invalid", varDef.name or varDef.id)
        end
    end

    -- Use shared validation for common validations, if validation is defined
    if varDef.validation then
        local varName = varDef.name or varDef.id
        local isValid, errorMsg = FieldValidator.validateValue(value, varDef.validation, varName)
        if not isValid then
        return false, errorMsg
        end
    end

    return true
end

-- Process variable definitions from input data and resolve variables
ValidationUtils.processVariableDefinitions = function(varDefs, variables)
    local processedDefs = {}
    for varId, varDef in pairs(varDefs) do
        -- If the value is a string, try to resolve it as a variable
        local processedDef = varDef
        if type(varDef) == "string" and variables then
            local resolvedValue = variables:tryResolveExactStringAsVariableObject(varDef)
            if resolvedValue then
                processedDef = resolvedValue
            end
        end
        processedDefs[varId] = processedDef
    end
    return processedDefs
end

-- Validate values against processed variable definitions
ValidationUtils.validateVariableValues = function(varDefs, values, dfsm)
    for varId, varDef in pairs(varDefs) do
        local varValue = values[varId]
        
        -- Check if the variable exists in values
        if varValue == nil then
            return false, string.format("Required variable '%s' is missing", varId)
        end
        
        -- Validate the variable using shared validation
        local isValid, errorMsg = ValidationUtils.validateVariable(varDef, varValue, dfsm)
        if not isValid then
            return false, errorMsg
        end
    end
    return true
end

-- Process variable definitions and validate values in one step
ValidationUtils.processAndValidateVariables = function(varDefs, values, dfsm)
    -- Step 1: Process variable definitions
    local processedDefs = ValidationUtils.processVariableDefinitions(varDefs, dfsm.variables)
    
    -- Step 2: Validate values against variable definitions
    return ValidationUtils.validateVariableValues(processedDefs, values, dfsm)
end

-- Base Verifier class
local BaseVerifier = {}
BaseVerifier.__index = BaseVerifier

function BaseVerifier:new()
    local self = setmetatable({}, BaseVerifier)
    return self
end

-- EIP712 Verifier implementation
local EIP712Verifier = BaseVerifier:new()
EIP712Verifier.__index = EIP712Verifier

function EIP712Verifier:new()
    local self = setmetatable({}, EIP712Verifier)
    return self
end

-- Shared VC validation logic for both EIP712 and EVMTransaction
local function validateInputVC(input, value, dfsm, validateSignature, validateValues)
    -- Default to not validating if not explicitly set
    validateSignature = validateSignature == true
    -- default to validate the values field in the credentialSubject
    if validateValues == nil then validateValues = true end
    local variables, documentHash = dfsm.variables, dfsm.documentHash
    local vcJson, credentialSubject, issuerAddress
    validateSignature = validateSignature == true
    if type(value) == "string" then
        if validateSignature then
            -- Use cryptographic validation in production
            local success, parsedVcJson, recoveredIssuerAddress = VcValidator.validate(value)
            if not success then
                return false, nil, "Invalid VC"
            end
            vcJson = parsedVcJson
            issuerAddress = recoveredIssuerAddress
        else
            vcJson = json.decode(value)
        end
    else
        vcJson = value
    end
    credentialSubject = vcJson.credentialSubject
    if not validateSignature and vcJson.issuer and vcJson.issuer.id then
        local id = vcJson.issuer.id
        local parts = {}
        for part in string.gmatch(id or "", "[^:]+") do
            table.insert(parts, part)
        end
        if #parts >= 5 and parts[1] == "did" and parts[2] == "pkh" then
            issuerAddress = parts[5]
        end
    end
    if not credentialSubject then
        return false, nil, "Missing credentialSubject in input"
    end
    if validateValues and not credentialSubject.values then
        return false, nil, "Missing values in credentialSubject"
    end
    local function normalizeHex(hex)
        if type(hex) ~= "string" then return hex end
        return hex:lower():gsub("^0x", "")
    end
    if normalizeHex(vcJson.credentialSubject.documentHash) ~= normalizeHex(documentHash) then
        return false, nil, "Input VC is targeting the wrong agreement"
    end
    if validateValues and input.data then
        local isValid, errorMsg = ValidationUtils.processAndValidateVariables(input.data, credentialSubject.values, dfsm)
        if not isValid then
            return false, nil, errorMsg
        end
    end
    if input.issuer and issuerAddress then
        local expectedIssuer = input.issuer
        if variables then
            local resolvedIssuer = variables:tryResolveExactStringAsVariableObject(expectedIssuer)
            if resolvedIssuer then
                expectedIssuer = resolvedIssuer
            end
        end
        if expectedIssuer and not ValidationUtils.ethAddressEqual(expectedIssuer, issuerAddress) then
            -- Extract variable name from the reference string (e.g. "variables.recipientEthAddress.value" -> "recipientEthAddress")
            local varName = input.issuer:match("variables%.([^%.]+)")
            -- Get the actual value for the error message
            local actualExpectedValue = variables and (varName and variables:getVariable(varName) or expectedIssuer) or expectedIssuer
            local errorMsg = string.format("Issuer mismatch: expected %s, got %s", actualExpectedValue, issuerAddress)
            return false, nil, errorMsg
        end
    end
    return true, vcJson, nil
end

function EIP712Verifier:verify(input, value, dfsm, validateSignature)
    local isValid, vcJson, errorMsg = validateInputVC(input, value, dfsm, validateSignature, true)
    if not isValid then
        return false, errorMsg
    end
    return true, vcJson.credentialSubject.values
end

-- Factory function to get the appropriate verifier
local function getVerifier(inputType)
    if not inputType then
        return nil, "Input type is missing"
    end

    local verifiers = {
        VerifiedCredentialEIP712 = EIP712Verifier:new(),
    }

    local verifier = verifiers[inputType]
    if not verifier then
        return nil, string.format("Unsupported input type: %s", inputType)
    end

    return verifier
end

-- Main verification function
local function verify(input, value, dfsm, validate)
    if not input then
        return false, "Input definition is nil"
    end

    local verifier, error = getVerifier(input.type)
    if not verifier then
        return false, error
    end

    return verifier:verify(input, value, dfsm, validate)
end


  __loaded["verifiers/input_verifier"] = {
    verify = verify,
    ValidationUtils = ValidationUtils,
}
  return __loaded["verifiers/input_verifier"]
end
-- End module: verifiers/input_verifier.lua

-- Begin module: contracts/contract_manager.lua
__modules["contracts/contract_manager"] = function()
  if __loaded["contracts/contract_manager"] then return __loaded["contracts/contract_manager"] end
local ContractManager = {}

local crypto = require(".crypto.init")
local json = require("json") -- You'll need a JSON library for Lua

-- Utility function to convert hex to bytes
local function hex_to_bytes(hex)
    hex = hex:gsub("^0x", "") -- Remove 0x prefix if present
    local bytes = {}
    for i = 1, #hex, 2 do
        local byte_str = hex:sub(i, i + 1)
        table.insert(bytes, tonumber(byte_str, 16))
    end
    return bytes
end

-- Utility function to convert bytes to hex
local function bytes_to_hex(bytes)
    local hex = ""
    for i, byte in ipairs(bytes) do
        hex = hex .. string.format("%02x", byte)
    end
    return "0x" .. hex
end

-- Utility function to extract a slice from bytes array
local function slice_bytes(bytes, start, length)
    local result = {}
    for i = start, start + length - 1 do
        table.insert(result, bytes[i])
    end
    return result
end

-- Utility function to convert bytes to integer
local function bytes_to_int(bytes)
    local result = 0
    for i, byte in ipairs(bytes) do
        result = result * 256 + byte
    end
    return result
end

-- Utility function to convert bytes to address (20 bytes)
local function bytes_to_address(bytes)
    return bytes_to_hex(bytes):sub(1, 42) -- 0x + 40 hex chars
end

-- Helper functions
-- EIP-712 specific functions
local function keccak256(input)
    return crypto.digest.keccak256(input).asHex()
end

-- Function to get function signature from function name and parameter types
local function get_function_signature(name, param_types)
    local signature = name .. "("
    for i, param_type in ipairs(param_types) do
        if i > 1 then signature = signature .. "," end
        signature = signature .. param_type
    end
    signature = signature .. ")"

    local hash = keccak256(signature)
    return string.sub(hash, 1, 8) -- First 4 bytes (8 hex chars + 0x)
end

-- Function to find matching function in ABI by signature
local function find_function_by_signature(abi, signature)
    for _, item in ipairs(abi) do
        if item.type == "function" then
            local param_types = {}
            for _, input in ipairs(item.inputs or {}) do
                table.insert(param_types, input.type)
            end
            local func_signature = get_function_signature(item.name, param_types)

            if func_signature == string.sub(signature, 3) then
                return item
            end
        end
    end
    return nil
end

-- Main function to decode transaction data
function decode_transaction_data(tx_data, abi_json)
    local abi = json.decode(abi_json)
    
    -- Remove 0x prefix if present
    tx_data = tx_data:gsub("^0x", "")
    
    -- If data is empty, it's a simple Ether transfer
    if #tx_data == 0 then
        return {
            function_name = "transfer",
            function_signature = "",
            parameters = {}
        }
    end
    
    -- Extract function signature (first 4 bytes)
    local signature = "0x" .. tx_data:sub(1, 8)
    local data_bytes = hex_to_bytes(tx_data)

    
    -- Find the matching function in the ABI
    local function_def = find_function_by_signature(abi, signature)
    if not function_def then
        return {
            function_name = "unknown",
            function_signature = signature,
            parameters = {}
        }
    end
    
    -- Decode parameters based on the function definition
    local parameters = {}
    local offset = 5 -- Start after the function signature (4 bytes)
    
    for i, input in ipairs(function_def.inputs or {}) do
        local param_value
        
        if input.type == "uint256" or input.type:match("^uint%d+$") then
            -- Decode uint256 (32 bytes)
            local value_bytes = slice_bytes(data_bytes, offset, 32)
            param_value = bytes_to_int(value_bytes)
            offset = offset + 32
        elseif input.type == "address" then
            -- Decode address (20 bytes, but padded to 32 bytes in calldata)
            local value_bytes = slice_bytes(data_bytes, offset + 12, 20) -- Skip 12 bytes of padding
            param_value = bytes_to_address(value_bytes)
            offset = offset + 32
        elseif input.type == "bool" then
            -- Decode boolean (1 byte, but padded to 32 bytes in calldata)
            local value_bytes = slice_bytes(data_bytes, offset, 32)
            param_value = bytes_to_int(value_bytes) ~= 0
            offset = offset + 32
        elseif input.type == "string" or input.type == "bytes" then
            -- Dynamic types have their offset at the current position
            local offset_bytes = slice_bytes(data_bytes, offset, 32)
            local data_offset = bytes_to_int(offset_bytes) * 2 + 9 -- Convert to bytes position in hex string (8 chars for func sig + 1 for 0x)
            
            -- Get length of string/bytes
            local length_bytes_pos = math.floor(data_offset / 2) + 1
            local length_bytes = slice_bytes(data_bytes, length_bytes_pos, 32)
            local length = bytes_to_int(length_bytes)
            
            -- Get actual string/bytes data
            local data_start = length_bytes_pos + 32
            local data_end = data_start + length - 1
            local value_bytes = slice_bytes(data_bytes, data_start, length)
            
            if input.type == "string" then
                -- Convert bytes to string
                local str = ""
                for _, b in ipairs(value_bytes) do
                    str = str .. string.char(b)
                end
                param_value = str
            else
                param_value = bytes_to_hex(value_bytes)
            end
            
            offset = offset + 32
        else
            -- For other types or complex types, return the raw bytes
            local value_bytes = slice_bytes(data_bytes, offset, 32)
            param_value = bytes_to_hex(value_bytes)
            offset = offset + 32
        end
        
        -- Add parameter to results
        table.insert(parameters, {
            name = input.name,
            type = input.type,
            value = param_value
        })
    end
    
    return {
        function_name = function_def.name,
        function_signature = signature,
        parameters = parameters
    }
end


function ContractManager.new(contracts)
    local self = {
        contracts = {}
    }

    for id, contract in pairs(contracts) do
        self.contracts[id] = {
            id = id,
            description = contract.description,
            address = contract.address,
            abi = contract.abi,
            get = function(self)
                return self.value
            end,
            setAddress = function(self, address)
                self.address = address
            end,
            decode = function(self, txInput)
                return decode_transaction_data(txInput, self.abi)
            end
        }
    end

    setmetatable(self, { __index = ContractManager })
    return self
end

function ContractManager:getContract(id)
    local contract = self.contracts[id]
    if not contract then
        error(string.format("Contract not found: %s", id))
    end
    return contract:get()
end

function ContractManager:setContractAddress(id, address)
    local contract = self.contracts[id]
    if not contract then
        error(string.format("Contract not found: %s", id))
    end
    contract:setAddress(address)
end

function ContractManager:getAllContracts()
    local result = {}
    for name, contract in pairs(self.contracts) do
        result[name] = {
            value = contract:get(),
        }
    end
    return result
end


  __loaded["contracts/contract_manager"] = ContractManager
  return __loaded["contracts/contract_manager"]
end
-- End module: contracts/contract_manager.lua

-- Begin module: dfsm.lua
__modules["dfsm"] = function()
  if __loaded["dfsm"] then return __loaded["dfsm"] end
-- DFSM (Deterministic Finite State Machine) implementation
local VariableManager = __modules["variables/variable_manager"]()
local InputVerifier = __modules["verifiers/input_verifier"]()
local json = require("json")
local VcValidator = __modules["vc-validator"]()
local ContractManager = __modules["contracts/contract_manager"]()
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

  __loaded["dfsm"] = {
    new = DFSM.new,
}
  return __loaded["dfsm"]
end
-- End module: dfsm.lua

-- Begin module: apoc-v2.lua
__modules["apoc-v2"] = function()
  if __loaded["apoc-v2"] then return __loaded["apoc-v2"] end


local json = require("json")
local Array = require(".crypto.util.array")
local crypto = require(".crypto.init")
local utils = require(".utils")
local base64 = require(".base64")

local DFSM = __modules["dfsm"]()


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
  local isWrappedVC = false
  if type(Data) == "string" then
    local parsed = json.decode(Data)
    isWrappedVC = parsed.credentialSubject and parsed.credentialSubject.agreement ~= nil
  elseif type(Data) == "table" then
    isWrappedVC = Data.credentialSubject and Data.credentialSubject.agreement ~= nil
  end

  local dfsm
  if isWrappedVC then
    -- Pass the original wrapped VC string to DFSM.new
    local wrappedVCString = type(msg.Data) == "string" and msg.Data or json.encode(msg.Data)
    dfsm = DFSM.new(wrappedVCString, true, initialValues)
  else
    local documentString = type(document) == "string" and document or json.encode(document)
    dfsm = DFSM.new(documentString, false, initialValues)
  end

  if not dfsm then
    print("[apoc-v2] DFSM.new returned nil!")
    reply_error(msg, 'Invalid agreement document')
    return false
  end

  Document = type(document) == "string" and json.decode(document) or document
  -- Calculate document hash from the original wrapped VC document, not the extracted agreement
  DocumentHash = crypto.digest.keccak256(type(msg.Data) == "string" and msg.Data or json.encode(msg.Data)).asHex()
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

  __loaded["apoc-v2"] = { 
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
  return __loaded["apoc-v2"]
end
-- End module: apoc-v2.lua

-- Custom require function
local function __require(moduleName)
  return __modules[moduleName]()
end

-- Main actor file: manifesto-actor.lua
local json = require("json")
local crypto = require(".crypto.init")

-- Import the extensible base actor
local BaseActor = __modules["apoc-v2"]()
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