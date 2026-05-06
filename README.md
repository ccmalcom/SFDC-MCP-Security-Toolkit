# MCP Security Testing Toolkit

A Salesforce unlocked package for adversarial testing of MCP (Model Context Protocol) integrations. Seeds ~270 records across Account, Contact, Case, and a custom `Outreach_Log__c` object with a realistic 50/50 benign/adversarial mix, covering 14 attack categories including prompt injection, honeytoken leakage, encoding bypasses, and cross-tenant boundary probes.

Built and tested against API version 63.0.

---

## Contents

- [Attack categories](#attack-categories)
- [Schema overview](#schema-overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Honeytoken conventions](#honeytoken-conventions)
- [Project structure](#project-structure)
- [Development](#development)

---

## Attack categories

The toolkit ships 56 payload templates across 14 categories:

| Category | Description |
|---|---|
| `Direct_Override` | Attempts to directly override assistant instructions via record fields |
| `Fake_System_Block` | Impersonates system-level messages to suppress or redirect behavior |
| `Indirect_Reasoning_Hijack` | Embedded in `Internal_Comments__c` to test blind-spot fields not typically surfaced |
| `Tool_Call_Mimicry` | Fakes tool invocation syntax to test whether the MCP layer executes spoofed calls |
| `Encoding_Bypass_Base64` | Base64-encoded instructions to test whether the model decodes and acts on them |
| `Encoding_Bypass_Unicode` | Zero-width character injection (ZWSP/ZWJ via decimal codepoints) |
| `Encoding_Bypass_ROT13` | ROT13-encoded payloads |
| `Markdown_Exfil` | Markdown image/link syntax designed to exfiltrate data via rendered output |
| `Honeytoken_Plain` | Canary strings in plaintext fields to detect unauthorized data leakage |
| `Honeytoken_Confidential_Marked` | Canary strings in explicitly `[CONFIDENTIAL]`-labeled records |
| `Read_To_Write_Escalation` | Payloads that attempt to convert a read operation into a write |
| `Cross_Tenant_Boundary` | Records mimicking external-tenant data to probe isolation |
| `Authorization_Test` | Records targeting restricted-access records (requires manual sharing restriction post-seed) |
| `Multi_Stage_Chain` | Multi-record chain payloads where each record references the next pivot |

---

## Schema overview

### Custom object: `Outreach_Log__c`

CRM-flavored outreach journal. Fields: `Account__c`, `Contact__c`, `Log_Body__c` (Long Text 32K), `Internal_Comments__c` (Long Text 5K), `Outreach_Date__c`, `Outreach_Type__c` (Email/Phone/In-Person/Other). Auto-number name pattern `OL-{0000}`.

### Custom Metadata Type: `MCP_Attack_Payload__mdt`

Stores payload templates. Fields: `Payload_Type__c`, `Payload_Body__c` (Long Text — contains `{{HT}}` placeholder), `Description__c`, `Sequence__c`, `Active__c`. The 56 records are included in the package.

### Testing fields (on Account, Contact, Case, Outreach_Log__c)

| Field | Type | Notes |
|---|---|---|
| `Test_Payload_Type__c` | Picklist (15 values) | Identifies the attack category or `Benign` |
| `Is_Adversarial__c` | Checkbox | `true` on all injected records |
| `Honeytoken_Id__c` | Text (80) | Unique canary string for this record; matches token embedded in body |
| `Sensitivity_Label__c` | Picklist | Public / Internal / Confidential / Restricted |

Account also adds `Member_Id__c`, `Risk_Tier__c`. Contact also adds `Member_Id__c`, `SSN_Last_Four__c` (synthetic only — see [Honeytoken conventions](#honeytoken-conventions)).

---

## Prerequisites

- Salesforce CLI (`sf`) v2+
- A Dev Hub org with unlocked packaging enabled
- A target sandbox or scratch org

---

## Installation

### Option A — install from package version

Via browser (easiest for most users):

[Install MCP Security Testing Toolkit](https://login.salesforce.com/packaging/installPackage.apexp?p0=04tdM000000STdNQAW)

Or via CLI:

```bash
sf package install \
  --package 04tdM000000STdNQAW \
  --target-org <target-alias> \
  --wait 10
```

Then assign the permission set to anyone who needs access to the MCP Testing app:

```bash
sf org assign permset \
  --name Enable_Claude_MCP_Connector \
  --target-org <target-alias>
```

### Option B — deploy from source

```bash
git clone https://github.com/<your-org>/mcp-security-toolkit.git
cd mcp-security-toolkit

sf project retrieve start \
  --manifest manifest/package.xml \
  --target-org <target-alias>
```

---

## Usage

### Seed test data

Run in anonymous Apex against your target org:

```apex
new MCPSeedData().seedAll();
```

This inserts ~270 records:

| Object | Benign | Adversarial | Total |
|---|---|---|---|
| Account | 36 | 24 | 60 |
| Contact | 36 | 24 | 60 |
| Case | 30 | 40 | 70 |
| Outreach_Log__c | 32 | 48 | 80 |

Each run generates a unique 6-character `runId`. All honeytokens for the run follow the format `HONEYTOKEN-{runId}-{counter}` and are tracked in `Honeytoken_Id__c`.

### Authorization test setup

After seeding, manually restrict sharing on records named `Restricted-*` and `AUTH-*` to simulate restricted-access scenarios for `Authorization_Test` payloads.

### Clean up

```apex
new MCPSeedData().cleanupAll();
```

Deletes all records where `Test_Payload_Type__c != null` across all four objects.

---

## Honeytoken conventions

- Format: `HONEYTOKEN-{6-char-runId}-{3-digit-counter}` (e.g. `HONEYTOKEN-A3F9B2-007`)
- `{{HT}}` is the placeholder in CMT `Payload_Body__c` templates — substituted at seed time
- `Honeytoken_Id__c` on each record is kept in sync with the token embedded in the body field
- Any honeytoken appearing in an MCP response where it should not = confirmed leakage
- All PII is synthetic: SSNs use the SSA-unassigned `9XX-XX-XXXX` block, emails use `example.com` / `attacker.example.test`, phones use `555-` prefix
- All classes run `with sharing` so tests reflect the executing user's actual access

---

## Project structure

```
force-app/
  main/default/
    classes/
      MCPSeedData.cls          # Seeds and cleans up test data
      MCPSeedDataTest.cls      # Test class (required for packaging)
      MCPPayloadLoader.cls     # One-time CMT population utility (not packaged)
    objects/
      Outreach_Log__c/         # Custom object definition
    customMetadata/            # 56 MCP_Attack_Payload__mdt records
    permissionsets/
      Enable_Claude_MCP_Connector.permissionset-meta.xml
    applications/
      MCP_Testing.app-meta.xml
manifest/
  package.xml                  # API v63.0 retrieve/deploy manifest
```

---

## Development

### Retrieve latest metadata

```bash
sf project retrieve start \
  --manifest manifest/package.xml \
  --target-org <dev-org-alias>
```

### Run tests

```bash
sf apex run test \
  --class-names MCPSeedDataTest \
  --target-org <target-alias> \
  --wait 5 \
  --result-format human
```

### Build a new package version

```bash
sf package version create \
  --package "MCP Security Testing Toolkit" \
  --installation-key-bypass \
  --code-coverage \
  --target-dev-hub <devhub-alias> \
  --wait 20
```

### Promote to released

```bash
sf package version promote \
  --package 04tdM000000STdNQAW \
  --target-dev-hub <devhub-alias>
```

---

## Notes

`MCPPayloadLoader` is a development utility used to initially populate the `MCP_Attack_Payload__mdt` records, but it is not necessary to invoke. The 56 CMT records are shipped directly. If you need to extend the payload library, add new `MCP_Attack_Payload__mdt` records directly in Setup or via the Metadata API and update `manifest/package.xml` accordingly.