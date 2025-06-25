-- Manifesto Actor
-- Extends the base actor with manifesto-specific functionality

local BaseActor = require("apoc-v2")
local ActorExtensions = require("actor-extensions")
local Handlers = BaseActor.Handlers

-- BEGIN: manifesto-specific state
Signers = Signers or {} -- Track signers: {address -> {name, timestamp, signatureHash}}
SignerCount = SignerCount or 0
-- END: manifesto-specific state

local function resetState()
  -- Reset base state
  BaseActor.resetState()
  -- Reset manifesto-specific state
  Signers = {}
  SignerCount = 0
end

-- Manifesto-specific extension functions
local function setupManifestoExtensions()
  -- Pre-input processing: Only check for duplicate signatures
  ActorExtensions.registerExtension(ActorExtensions.ExtensionPoints.PRE_INPUT_PROCESSING, function(context)
    local inputValue = context.data.inputValue
    if inputValue and inputValue.credentialSubject and inputValue.credentialSubject.inputId == "signManifesto" then
      local signerAddress = inputValue.credentialSubject.values and inputValue.credentialSubject.values.signerAddress
      if signerAddress and Signers[signerAddress] then
        return { error = "Duplicate signature from address: " .. signerAddress }
      end
    end
    return { success = true }
  end)

  -- Post-input processing: Track new signers only after successful processing
  ActorExtensions.registerExtension(ActorExtensions.ExtensionPoints.POST_INPUT_PROCESSING, function(context)
    local inputValue = context.data.inputValue
    if inputValue and inputValue.credentialSubject and inputValue.credentialSubject.inputId == "signManifesto" then
      local signerAddress = inputValue.credentialSubject.values and inputValue.credentialSubject.values.signerAddress
      if signerAddress and not Signers[signerAddress] then
        Signers[signerAddress] = {
          address = signerAddress,
          timestamp = context.timestamp
        }
        SignerCount = SignerCount + 1
      end
    end
    return { success = true }
  end)

  -- State query: Add manifesto-specific state to queries
  ActorExtensions.registerExtension(ActorExtensions.ExtensionPoints.STATE_QUERY, function(context)
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