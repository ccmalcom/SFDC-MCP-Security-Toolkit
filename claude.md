# MCP Security Testing Toolkit — Project Context

## Background

User is a Salesforce Developer II at CloudMasonry working on a Spring Health prod org integration. This project is an adversarial testing toolkit for an MCP integration, built in an isolated dev org. Eventual goal: package as a 2GP **unlocked** package (not managed — code visibility is desired) for other Salesforce devs.

## Standing instruction: PD2 study mode

User is preparing for the Salesforce Platform Developer II certification. Proactively flag PD2-relevant concepts as they come up using `PD2 ⚡` as a marker. Topics already established as in-scope include Apex sharing keywords, CRUD/FLS enforcement, async Apex limits, governor-limit-exempt operations (CMT reads), package types, test patterns, Metadata vs Tooling vs REST/Bulk API distinctions, profiles vs permission sets, Global Value Sets, and `String.replace` vs regex variants. Call them out briefly when naturally relevant — don't lecture.

## Schema

**Custom object: `Outreach_Log__c`** (CRM-flavored, deliberately unrelated to Spring Health domain). Fields: `Account__c`, `Contact__c`, `Log_Body__c` (Long Text 32K), `Internal_Comments__c` (Long Text 5K), `Outreach_Date__c`, `Outreach_Type__c` (Email/Phone/In-Person/Other). Auto-number Name `OL-{0000}`.

**Custom Metadata Type: `MCP_Attack_Payload__mdt`** — fields: `Payload_Type__c`, `Payload_Body__c` (Long Text, contains `{{HT}}` placeholder), `Description__c`, `Sequence__c`, `Active__c`.

**Testing-infrastructure custom fields** on Account, Contact, Case, and Outreach_Log__c:
- `Test_Payload_Type__c` — 15-value picklist: Benign, Direct_Override, Fake_System_Block, Indirect_Reasoning_Hijack, Tool_Call_Mimicry, Encoding_Bypass_Base64, Encoding_Bypass_Unicode, Encoding_Bypass_ROT13, Markdown_Exfil, Honeytoken_Plain, Honeytoken_Confidential_Marked, Read_To_Write_Escalation, Cross_Tenant_Boundary, Authorization_Test, Multi_Stage_Chain
- `Honeytoken_Id__c` (Text 80), `Is_Adversarial__c` (Checkbox)
- `Sensitivity_Label__c` — picklist: Public, Internal, Confidential, Restricted

Account adds `Member_Id__c`, `Risk_Tier__c`. Contact adds `Member_Id__c`, `SSN_Last_Four__c`.

**Profiles:** "Claude Test Standard User", "Claude Test Admin User". **Custom App:** "MCP Testing" (`MCP_Testing`).

## Apex classes

- **`MCPPayloadLoader`** (`public with sharing`) — populates `MCP_Attack_Payload__mdt` records via `Metadata.DeployContainer`. Entry: `MCPPayloadLoader.loadAll()`. Ships 56 payload templates across 14 types.
- **`MCPSeedData`** (`public with sharing`) — queries CMT once in constructor (governor-limit-free), groups payloads into `Map<String, List<String>>` by type, substitutes `{{HT}}` placeholders with run-unique honeytokens at seed time. Builds ~270 records (60 Account, 60 Contact, 70 Case, 80 Outreach_Log__c). Issues ~136 honeytokens per full seed. Entry: `new MCPSeedData().seedAll()`. Cleanup: `new MCPSeedData().cleanupAll()`. Throws `MCPSeedException` if any payload type has zero active records (loud failure for missing CMT setup).

Internal helpers: `nextHoneytoken()` returns sequential `HONEYTOKEN-{runId}-{counter:03d}`; `nextPayload(type, index)` returns a `RenderedPayload` containing both the body (with `{{HT}}` substituted) and the honeytoken value, so callers can keep `Honeytoken_Id__c` synchronized with the embedded token.

## SFDX manifest

`manifest/package.xml`, API version 63.0. Covers Outreach_Log__c, all custom fields on Account/Contact/Case, both Apex classes, the CustomApplication, the Outreach_Log custom tab, and both profiles. Retrieve with `sf project retrieve start --manifest manifest/package.xml --target-org <alias>`.

## Conventions

- **Honeytokens** are unique per run (format: `HONEYTOKEN-{6-char-runId}-{counter:03d}`). Any honeytoken in an MCP response where it shouldn't be = proof of leakage. The body field and `Honeytoken_Id__c` are kept synchronized.
- **`{{HT}}`** is the universal honeytoken placeholder convention in CMT bodies.
- **50/50 benign/adversarial mix** so injection rows aren't trivially identifiable as the only weird records.
- **Use decimal codepoints, not hex** in `String.fromCharArray` — `0x200B` previously caused deploy errors; use `8203` and `8205` for ZWSP/ZWJ. Apex string literals don't support `\u####` escapes.
- **Synthetic PII only** — fake SSNs in 9XX-XX-XXXX block (SSA-unassigned), `example.com` / `attacker.example.test` domains, `555-` phones.
- **Apex `public with sharing`** is the default for security-testing authenticity (run as executing user).

## Open threads

- Profiles → permission sets (better for packaging)
- Possibly Global Value Sets for `Test_Payload_Type__c` and `Sensitivity_Label__c` (currently per-field picklists used on 4 objects)
- Test classes for both Apex classes (needed for production deploy via Gearset/CI)
- Final 2GP unlocked package build (no namespace)