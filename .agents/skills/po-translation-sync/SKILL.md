---
name: po-translation-sync
description: >-
  Procedure for maintaining, updating, and validating GNU Gettext PO translation catalogs
  in PassWall 2 across Persian (fa), Chinese, Russian, and other locales.
---

# PO Translation Sync Skill

This skill provides step-by-step instructions for updating and verifying GNU Gettext PO translation files in `luci-app-passwall2/po/`.

## Locales Overview
- `po/fa/passwall2.po`: Persian (Farsi) — First-class RTL language
- `po/zh-cn/passwall2.po` & `po/zh_Hans/passwall2.po`: Simplified Chinese
- `po/zh-tw/passwall2.po` & `po/zh_Hant/passwall2.po`: Traditional Chinese
- `po/ru/passwall2.po`: Russian

## Operational Procedures

### 1. Extracting / Identifying Untranslated Strings
When a new UI option is added in `luasrc/`:
1. Identify the newly introduced string: `translate("New Feature Name")`.
2. Add the corresponding `msgid` and `msgstr` entries in the target locale PO files:
   ```po
   msgid "New Feature Name"
   msgstr "نام ویژگی جدید"
   ```

### 2. Format Specifiers & Placeholders Rules
- If `msgid` contains `%s`, `%d`, or variables like `\n`:
  - `msgstr` MUST contain the exact same specifiers.
  - Failure to preserve specifiers will cause LuCI runtime errors or string formatting crashes.

### 3. Syntax & Structure Validation
- OpenWrt LuCI compiles translation catalogs into bytecode using `po2lmo` (often omitting standard gettext headers in raw `.po` files).
- Validate that all quotes and strings are properly balanced and that no unescaped quotes break the catalog:
  ```sh
  find luci-app-passwall2/po -name "*.po"
  ```

### 4. Done When
- [ ] No unmatched quotes or broken syntax corrupt PO catalogs.
- [ ] Persian RTL translations maintain standard networking terminology.
