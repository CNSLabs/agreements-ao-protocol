-- Explicitly importing secp256k1 and exposing recover_public_key, which is a global var in our custom AO module.
local secp256k1 = require("secp256k1")
local recover_public_key = secp256k1.recover_public_key

local json = require("json")
local Array = require(".crypto.util.array")
local crypto = require(".crypto.init")

local eip712 = require(".eip712")

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
    -- eg. 'did:ethr:0x1e8564A52fc67A68fEe78Fc6422F19c07cFae198'
    elseif (parts[1] == 'did' and parts[2] == 'ethr') then
      eth_address = parts[3]
    else
      error('Only supporting did:pkh and did:ethr issuers')
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

return {
  validate = vc_validate,
  get_authority = get_authority,
}