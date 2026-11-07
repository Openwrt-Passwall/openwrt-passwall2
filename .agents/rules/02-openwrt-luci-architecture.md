# Rule 02: OpenWrt LuCI Architecture & Conventions

This rule defines the architectural patterns and development standards for OpenWrt LuCI applications within PassWall 2.

---

## 1. LuCI Application Structure
PassWall 2 adheres to the OpenWrt LuCI MVC/CBI design pattern:
- **Controllers (`luasrc/controller/passwall2.lua`)**:
  - Handles routing, web authentication, and menu declarations via `entry()`.
  - Exposes JSON endpoints for asynchronous status polling, node pinging, log viewing, and rules updating.
  - Interacts with system services using `luci.sys.call()`, `luci.util.exec()`, or ubus calls.
- **Models / CBI (`luasrc/model/cbi/passwall2/`)**:
  - Defines configuration forms bound directly to `/etc/config/passwall2` using the LuCI CBI (Configuration Binding Interface) framework.
  - Core components: `Map`, `NamedSection`, `TypedSection`, `Value`, `ListValue`, `Flag`, `DynamicList`, `MultiValue`.
  - Always validate dependencies between fields using `.depends("option_name", "expected_value")`.
- **Views / Templates (`luasrc/view/passwall2/` & `htdocs/luci-static/`)**:
  - Renders custom HTML/JavaScript components (node selector widgets, real-time traffic graphs, diagnostic logs).
  - Modern LuCI views use client-side JavaScript (`luci-static/resources/view/`) communicating via `luci.dispatcher` JSON APIs or `rpcd`/`ubus`.

## 2. Lua 5.1 Constraints
- OpenWrt targets Lua 5.1 (or LuaJIT with 5.1 compatibility).
- **Prohibited**:
  - Native bitwise operators (`&`, `|`, `~`, `>>`). Use `nixio.bit` or `bit` library functions (`bit.band`, `bit.bor`, `bit.rshift`).
  - Integer division operator (`//`). Use `math.floor(a / b)`.
  - The `goto` statement and labels (unless verified for the target OpenWrt Lua runtime).
  - Table unpack changes: Use `unpack` instead of `table.unpack`.
- Always remember Lua arrays are **1-indexed**.

## 3. UCI (Unified Configuration Interface) Conventions
- Read options using the project's helper wrappers:
  `uci_get("passwall2", section, option, default)`
- Write options cleanly:
  `uci_set("passwall2", section, option, value)`
- Always call `uci_save()` and `uci_commit()` only when transactional changes are complete to avoid excessive flash write wear.
- Anonymous sections (e.g. `nodes`, `shunt_rules`) must be iterated via `uci_foreach()`.

## 4. OpenWrt Makefile Standards
- Package definition in `luci-app-passwall2/Makefile` must strictly use OpenWrt build macros:
  - `include $(TOPDIR)/rules.mk`
  - `PKG_NAME:=luci-app-passwall2`
  - `LUCI_DEPENDS:=...`
- Respect package architecture dependencies (`LUCI_PKGARCH:=all`).
- When introducing dependencies on helper tools (e.g. `chinadns-ng`, `xray-core`, `sing-box`), declare them under the appropriate config menus (`Package/$(PKG_NAME)/config`).
