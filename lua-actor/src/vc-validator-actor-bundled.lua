-- TODO: BEGIN remove lines before copying the actor logic into the backend service
-- local Handlers = require("Handlers")
-- local secp256k1 = require("secp256k1")
-- local recover_public_key = secp256k1.recover_public_key
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

-- Custom require function
local function __require(moduleName)
  return __modules[moduleName]()
end

-- Main actor file: vc-validator-actor.lua


local vc_validator_module = __modules["vc-validator"]()

Handlers.add(
  "ValidateVC",
  Handlers.utils.hasMatchingTag("Action", "ValidateVC"),
  function (msg)
    -- expecting msg.Data to contain a VC to validate
    local vc_data = msg.Data

    if not vc_data or vc_data == "" then
      msg.reply({
        Data = {
          success = false,
          error = "No VC data provided"
        }
      })
      return
    end

    -- Validate the VC using the vc-validator library
    local success, result = pcall(vc_validator_module.validate, vc_data)
    
    if success then
      local vc_json, owner_eth_address = result
      msg.reply({
        Data = {
          success = true,
          issuerAddress = owner_eth_address
        }
      })
    else
      msg.reply({
        Data = {
          success = false,
          error = result
        }
      })
    end
  end
)

return { Handlers = Handlers }
