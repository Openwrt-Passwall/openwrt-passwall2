---
name: luci-component-builder
description: >-
  Guide and procedural runbook for creating or modifying LuCI CBI models, controllers,
  view templates, and client-side JavaScript components in PassWall 2.
---

# LuCI Component Builder Skill

This skill provides step-by-step procedures for extending or modifying the LuCI user interface in PassWall 2.

## Operational Workflow

### 1. Adding or Modifying a CBI Model
1. Navigate to the appropriate CBI model in `luasrc/model/cbi/passwall2/`.
2. Ensure you obtain the Map object correctly:
   ```lua
   local m = Map("passwall2", translate("PassWall 2 Settings"))
   ```
3. When adding sections, choose between `NamedSection` (for singleton configs like `global`) or `TypedSection` (for lists like `nodes`):
   ```lua
   local s = m:section(NamedSection, "global", "global", translate("Global Settings"))
   s.anonymous = true
   s.addremove = false
   ```
4. Define fields with appropriate types:
   - Boolean toggles: `s:option(Flag, "enabled", translate("Enable"))`
   - Dropdowns: `s:option(ListValue, "tcp_node", translate("TCP Node"))`
   - Text inputs: `s:option(Value, "port", translate("Port"))`
   - Multi-values: `s:option(DynamicList, "shunt_rule", translate("Shunt Rules"))`
5. Chain dependencies:
   ```lua
   local o = s:option(Value, "remote_dns", translate("Remote DNS"))
   o:depends("dns_mode", "custom")
   ```

### 2. Adding a Controller Endpoint
1. Open `luasrc/controller/passwall2.lua`.
2. Register the endpoint in `index()`:
   ```lua
   entry({"admin", "services", appname, "custom_action"}, call("action_custom"), nil).leaf = true
   ```
3. Implement the handler function returning JSON or status:
   ```lua
   function action_custom()
       local http = require "luci.http"
       local data = { status = "ok", timestamp = os.time() }
       http.prepare_content("application/json")
       http.write(luci.jsonc.stringify(data))
   end
   ```

### 3. Verification Protocol
1. Check Lua syntax:
   `lua -p luasrc/controller/passwall2.lua`
2. Ensure translated strings are wrapped in `translate("...")`.
3. Test that no nil index errors or syntax regressions are introduced.
