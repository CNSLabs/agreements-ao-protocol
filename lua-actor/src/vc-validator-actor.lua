local Handlers = require("handlers")

local vc_validator_module = require("vc-validator")

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
