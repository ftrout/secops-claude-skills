# Azure investigation reference

Contents: log sources; identity kinds; high-signal operations by phase; KQL for
AzureActivity, AuditLogs, and diagnostics; preservation; containment.

Accurate as of September 2026 for Log Analytics table names and Activity Log
`OperationNameValue` strings. Microsoft renames things; when a query returns nothing,
check the table schema in the workspace before assuming the activity did not happen.

Azure incidents straddle two planes. Entra ID (the tenant: users, apps, service
principals, roles) and Azure Resource Manager (subscriptions, resource groups, resources).
An attacker usually enters through Entra and pivots to ARM, or steals a managed identity /
service principal secret and skips Entra sign-in analysis entirely. Cover both.

## Log sources and what each answers

| Source | Table | Answers | Notes |
|---|---|---|---|
| Activity Log | `AzureActivity` | ARM control-plane writes: role assignments, resource create/delete, key listings, run commands | 90 days in the portal; longer only if sent to Log Analytics or storage. Reads are not logged |
| Entra sign-in logs | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs` | who authenticated, from where, with what MFA and CA result, to which app | interactive vs non-interactive split matters: token refreshes live in the non-interactive table. Owned by `identity-threat-investigation` for the user side |
| Entra audit logs | `AuditLogs` | directory changes: role adds, app credential adds, consent, CA policy changes, federation changes | the persistence log |
| Microsoft Graph activity | `MicrosoftGraphActivityLogs` | Graph API calls by app and user (mail reads, directory enumeration) | must be enabled via diagnostic settings on the tenant |
| Resource diagnostics | `AzureDiagnostics` (legacy) or resource-specific tables such as `AZKVAuditLogs`, `StorageBlobLogs`, `AzureNetworkAnalytics_CL` | data-plane: Key Vault secret reads, blob reads, NSG flows | per-resource diagnostic settings; off by default |
| Defender for Cloud / XDR | `SecurityAlert`, `SecurityIncident` | managed detections with entity context | still go to the raw tables |
| Microsoft Defender for Cloud Apps | `CloudAppEvents` (via Defender XDR) | SaaS and Office activity, OAuth app use | useful for M365 blast radius |
| Office / M365 audit | `OfficeActivity` | mailbox, SharePoint, Teams operations | for mailbox rules and data access after an identity compromise |
| Resource Graph / change analysis | portal, `az graph` | current state and recent property changes of resources | for "what does this look like now" |

## Identity kinds you will meet

| Kind | Sign-in table | Credential | Notes |
|---|---|---|---|
| User | `SigninLogs`, `AADNonInteractiveUserSignInLogs` | password + MFA, token | `identity-threat-investigation` |
| Service principal (app) | `AADServicePrincipalSignInLogs` | client secret or certificate | `ServicePrincipalId`, `AppId`; secrets are added via `AuditLogs` "Add service principal credentials" |
| Managed identity | `AADManagedIdentitySignInLogs` | none (platform-issued) | compromise means compromise of the resource it is attached to (VM, App Service, Function, AKS) |
| Guest / external user | `SigninLogs` with `UserType = Guest` | home tenant | check `HomeTenantId` and who invited them |
| Delegated admin (GDAP / partner) | `SigninLogs` with `CrossTenantAccessType` | partner tenant | "Add partner to company" in `AuditLogs` is a tenant-level backdoor |

In `AzureActivity`, `Caller` is the UPN or object ID, `CallerIpAddress` the source, and
`Authorization_d` / `Claims_d` carry the app ID and auth method. Service principal calls
show the app's object ID as `Caller`.

## High-signal operations by phase

**Entra directory changes (`AuditLogs.OperationName`)**
- `Add service principal credentials`, `Update application - Certificates and secrets management` (persistence via app secret)
- `Add owner to application`, `Add owner to service principal`
- `Consent to application`, `Add app role assignment grant to user`, `Add delegated permission grant`, `Add app role assignment to service principal` (Graph permissions such as `Mail.Read`, `Directory.ReadWrite.All`)
- `Add member to role`, `Add eligible member to role`, `Add member to role in PIM requested (permanent)`; watch Global Administrator, Privileged Role Administrator, Application Administrator, Cloud Application Administrator, Exchange Administrator
- `Update conditional access policy`, `Delete conditional access policy`, `Add conditional access policy` (named locations that exclude the attacker's IP)
- `Set federation settings on domain`, `Set domain authentication`, `Add unverified domain`, `Verify domain` (federated backdoor)
- `Add partner to company` (delegated admin relationship)
- `User registered security info`, `Admin registered security info`, `Reset password (by admin)`, `Update user` with `StrongAuthenticationMethod` changes
- `Add user`, `Invite external user`, `Redeem external user invite`
- `Disable Strong Authentication`, `Update policy` (authentication methods policy)

**ARM control plane (`AzureActivity.OperationNameValue`, uppercase as logged)**
- `MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE` (Owner / Contributor / User Access Administrator at subscription or management group scope is the escalation)
- `MICROSOFT.AUTHORIZATION/ROLEDEFINITIONS/WRITE` (custom role with broad actions)
- `MICROSOFT.AUTHORIZATION/POLICYASSIGNMENTS/DELETE`, `MICROSOFT.AUTHORIZATION/LOCKS/DELETE`
- `MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE`, `MICROSOFT.INSIGHTS/LOGPROFILES/DELETE` (logging tamper)
- `MICROSOFT.SECURITY/PRICINGS/WRITE` (Defender plan downgraded), `MICROSOFT.SECURITY/AUTOPROVISIONINGSETTINGS/WRITE`
- `MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE`, `MICROSOFT.KEYVAULT/VAULTS/WRITE` (network rules or RBAC changes)
- `MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION`, `MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION`, `MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE` (public access, network rules)
- `MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION`, `MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE` (code execution on VMs)
- `MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION` (SAS export of a disk), `MICROSOFT.COMPUTE/SNAPSHOTS/WRITE`
- `MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE` (new compute, mining), `MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE`
- `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE`, `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE`
- `MICROSOFT.WEB/SITES/CONFIG/LIST/ACTION` (App Service app settings, including connection strings), `MICROSOFT.WEB/SITES/PUBLISHXML/ACTION` (deployment credentials)
- `MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE`, `.../JOBS/WRITE` (persistence with the automation account's identity)
- `MICROSOFT.MANAGEDIDENTITY/USERASSIGNEDIDENTITIES/WRITE`, `MICROSOFT.MANAGEDIDENTITY/USERASSIGNEDIDENTITIES/FEDERATEDIDENTITYCREDENTIALS/WRITE` (workload identity federation backdoor)
- `MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE` (ARM template deployments: check the template for embedded secrets or new principals)
- `MICROSOFT.SQL/SERVERS/FIREWALLRULES/WRITE`, `MICROSOFT.SQL/SERVERS/ADMINISTRATORS/WRITE`

**Data plane**
- Key Vault (`AZKVAuditLogs` or `AzureDiagnostics` with `ResourceType == "VAULTS"`): `OperationName` in `SecretGet`, `SecretList`, `KeyGet`, `CertificateGet`, `VaultGet`; `ResultSignature` 200 vs 403; `CallerIPAddress`; bursts of `SecretList` then `SecretGet` are the collection pattern
- Storage (`StorageBlobLogs`): `OperationName` in `GetBlob`, `ListBlobs`, `PutBlob`, `DeleteBlob`; `AuthenticationType` (SAS, AccountKey, OAuth) tells you which credential was used; `AccountKey` after a `LISTKEYS/ACTION` is the tell
- Graph (`MicrosoftGraphActivityLogs`): `RequestUri` containing `/users`, `/groups`, `/applications`, `/me/messages`; `AppId` of the caller

## KQL examples

```kusto
// Everything an identity did on the ARM plane, with parsed authorization
AzureActivity
| where TimeGenerated between (datetime(2026-09-07) .. datetime(2026-09-15))
| where Caller =~ "alice.dev@yourcompany.example" or Caller == "<object-id>"
| project TimeGenerated, OperationNameValue, ActivityStatusValue, ResourceGroup, _ResourceId,
          CallerIpAddress, Authorization_d.evidence.role, Claims_d.appid, Properties
| order by TimeGenerated asc

// Role assignments created, with target scope and principal
AzureActivity
| where OperationNameValue =~ "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE"
| where ActivityStatusValue =~ "Success"
| extend props = parse_json(Properties)
| extend body = parse_json(tostring(parse_json(tostring(props.requestbody))))
| project TimeGenerated, Caller, CallerIpAddress, Scope = tostring(props.scope),
          PrincipalId = tostring(body.Properties.PrincipalId),
          RoleDefinitionId = tostring(body.Properties.RoleDefinitionId)

// Logging and protection tampering
AzureActivity
| where OperationNameValue in~ ("MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE",
    "MICROSOFT.SECURITY/PRICINGS/WRITE", "MICROSOFT.AUTHORIZATION/POLICYASSIGNMENTS/DELETE",
    "MICROSOFT.AUTHORIZATION/LOCKS/DELETE")
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, _ResourceId, ActivityStatusValue

// Storage key listing followed by key-authenticated blob access
let keyListers = AzureActivity
  | where OperationNameValue =~ "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION"
  | where TimeGenerated > ago(7d)
  | project ListTime = TimeGenerated, Caller, CallerIpAddress, Account = tolower(_ResourceId);
StorageBlobLogs
| where TimeGenerated > ago(7d) and AuthenticationType == "AccountKey"
| extend Account = tolower(_ResourceId)
| join kind=inner keyListers on Account
| where TimeGenerated > ListTime
| summarize Ops = count(), Reads = countif(OperationName == "GetBlob"), FirstOp = min(TimeGenerated)
      by Account, Caller, CallerIpAddress, ClientIp = CallerIpAddress1

// Key Vault secret reads by caller (resource-specific table)
AZKVAuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in ("SecretGet", "SecretList", "KeyGet", "CertificateGet")
| summarize Count = count(), Denied = countif(ResultSignature != "200"),
            Secrets = make_set(Id, 20), IPs = make_set(CallerIPAddress, 10)
      by tostring(Identity.claim.upn), tostring(Identity.claim.appid), bin(TimeGenerated, 1h)
| order by Count desc
// Legacy schema: AzureDiagnostics | where ResourceType == "VAULTS" | where OperationName == "SecretGet"

// Service principal credential additions and consent grants
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Add service principal credentials", "Consent to application",
    "Add app role assignment to service principal", "Add member to role",
    "Add eligible member to role", "Update conditional access policy",
    "Set federation settings on domain", "Add partner to company")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName),
         ActorApp = tostring(InitiatedBy.app.displayName),
         Target = tostring(TargetResources[0].displayName),
         Changes = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, OperationName, Result, Actor, ActorApp, Target, Changes

// Service principal sign-ins from new IPs
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(7d)
| summarize Count = count(), IPs = make_set(IPAddress, 20), Resources = make_set(ResourceDisplayName, 10)
      by ServicePrincipalName, AppId
| where array_length(IPs) > 1

// VM run commands and extensions (code execution on compute)
AzureActivity
| where OperationNameValue in~ ("MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE")
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId, ActivityStatusValue, Properties
```

## Preservation

- **Activity Log:** portal retention is 90 days. Confirm a diagnostic setting sends it to
  a Log Analytics workspace or storage account, then export the window (Log Analytics
  "Export" or `az monitor activity-log list` to JSON) to the forensic subscription.
- **Entra logs:** default retention in Entra is 30 days (P1/P2 tenants) and shorter for
  free tenants; the Log Analytics copy has whatever retention the workspace sets. Export
  `SigninLogs`, `AuditLogs`, and the non-interactive / service principal tables for the
  window now.
- **Compute:** create a snapshot of each OS and data disk (incremental snapshots are fine),
  then copy to the forensic subscription. Do not deallocate if memory matters; isolate via an
  NSG that denies all, remove from load balancers, and remove the managed identity's role
  assignments rather than deleting the identity.
- **Key Vault:** soft delete and purge protection determine whether deleted secrets are
  recoverable. Record which secrets were read (from `AZKVAuditLogs`) before rotating them.
- **App Service / Functions:** download the deployment (Kudu `zip` or the storage-backed
  package) and capture app settings; they often contain the leaked connection string.
- **Entra state:** export role assignments (`Get-MgRoleManagementDirectoryRoleAssignment`),
  app registrations with credentials, service principal owners, and conditional access
  policies as JSON at the start.

## Containment

| Action | Where | Blast radius and cautions |
|---|---|---|
| Revoke a user's tokens and sessions | Entra: "Revoke sessions" / `Revoke-MgUserSignInSession`, then reset password and MFA | primary refresh tokens on managed devices may persist until device compliance re-evaluates; see `identity-threat-investigation` |
| Disable a service principal | Entra: set `accountEnabled = false` on the SP; remove its credentials (`Remove-MgServicePrincipalPassword`) | breaks whatever automation uses it; prefer removing the *attacker-added* credential only if you can distinguish it by `keyId` and creation date |
| Remove an ARM role assignment | `az role assignment delete` | check for role assignments at management group scope and for deny assignments the attacker may have created |
| Rotate storage account keys | `REGENERATEKEY` (key1 then key2) | every client using the old key breaks; SAS tokens signed with that key die too |
| Rotate Key Vault secrets | new secret version; update consumers | do not disable the vault; consumers fail. Record the read set first |
| Block an IP tenant-wide | Conditional Access named location + block policy | CA does not apply to already-issued tokens until they refresh |
| Stop code execution on a VM | remove run command permissions from the caller; NSG isolation | VM extensions the attacker installed persist across reboots; remove them |
| Prevent recurrence | Azure Policy deny on public storage, resource locks on log settings, Defender plans re-enabled, PIM for privileged roles | Azure Policy deny evaluates on write; existing resources need remediation |
| Delegated admin backdoor | Entra: remove the partner relationship | verify with the partner before removal if it is legitimate |

After containment, re-run the `AzureActivity` and sign-in queries for the contained
principals. Successful operations mean a credential was missed (often a second app secret
or a managed identity).
