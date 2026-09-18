# Entra ID (Azure AD) investigation reference

Contents: tables and fields; sign-in result codes; risk detection names; token replay and
AiTM indicators; KQL for sign-ins, consent, MFA changes, mailbox rules, privilege; containment
order with cautions.

Accurate as of September 2026 for Log Analytics table and field names. Microsoft renames
things; if a query returns nothing, check the table schema first.

## Tables

| Table | What | Key fields |
|---|---|---|
| `SigninLogs` | interactive user sign-ins | `UserPrincipalName`, `IPAddress`, `Location` (city/state/countryOrRegion), `ResultType`, `ResultDescription`, `AuthenticationRequirement`, `MfaDetail`, `AuthenticationDetails`, `ConditionalAccessStatus`, `ConditionalAccessPolicies`, `ClientAppUsed`, `UserAgent`, `AppDisplayName`, `AppId`, `DeviceDetail`, `RiskLevelDuringSignIn`, `RiskState`, `RiskEventTypes_V2`, `SessionId`, `CorrelationId`, `UniqueTokenIdentifier`, `AutonomousSystemNumber`, `NetworkLocationDetails`, `TokenIssuerType` |
| `AADNonInteractiveUserSignInLogs` | token refreshes and background sign-ins | same shape plus `IncomingTokenType` (`primaryRefreshToken`, `refreshToken`, ...) and `OriginalRequestId` |
| `AADServicePrincipalSignInLogs` | app (client credential) sign-ins | `ServicePrincipalName`, `AppId`, `IPAddress`, `ResourceDisplayName`, `ResultType` |
| `AADManagedIdentitySignInLogs` | managed identity token requests | `ServicePrincipalId`, `ResourceDisplayName` |
| `AuditLogs` | directory changes | `OperationName`, `Category`, `Result`, `InitiatedBy` (user / app), `TargetResources` (with `modifiedProperties`) |
| `AADUserRiskEvents` | Identity Protection detections | `RiskEventType`, `RiskLevel`, `RiskState`, `DetectionTimingType`, `IpAddress`, `Location` |
| `AADRiskyUsers` | current user risk | `RiskLevel`, `RiskState`, `RiskLastUpdatedDateTime` |
| `OfficeActivity` | Exchange, SharePoint, Teams operations | `Operation`, `UserId`, `ClientIP`, `Parameters`, `OfficeWorkload` |
| `MicrosoftGraphActivityLogs` | Graph API calls | `UserId`, `AppId`, `RequestUri`, `RequestMethod`, `IPAddress`, `UserAgent` |
| `CloudAppEvents` (Defender XDR) | M365 and SaaS activity with Defender for Cloud Apps enrichment | `ActionType`, `AccountUpn`, `IPAddress`, `ISP`, `RawEventData` |

## Sign-in `ResultType` codes worth knowing

| Code | Meaning | Investigation note |
|---|---|---|
| 0 | success | |
| 50126 | invalid username or password | spray / stuffing when many users from one IP; single user in bursts is guessing |
| 50034 | user not found | spray with a wordlist |
| 50053 | account locked, or sign-in blocked from a malicious IP | Smart Lockout tripped |
| 50055 / 50144 | password expired (cloud / on-prem) | |
| 50057 | account disabled | attacker probing a disabled account |
| 50074 | strong authentication (MFA) required | password was correct; MFA stopped it |
| 50076 | MFA required due to new location or device | password was correct |
| 50072 / 50079 | user must enroll MFA / security info | password correct; if the attacker enrolls, they own the MFA |
| 500121 | authentication failed during strong authentication request | the MFA push was denied, timed out, or wrong code: MFA fatigue signature in bursts |
| 50158 | external security challenge not satisfied | third-party MFA blocked it |
| 53003 | blocked by Conditional Access | policy did its job; check which |
| 53000 / 53001 | device not compliant / not joined | CA device rule blocked it |
| 50097 | device authentication required | |
| 50173 | fresh auth token needed | session was revoked or expired |
| 65001 | user or admin has not consented | app needs consent; watch for a consent right after |
| 70044 | session expired | |
| 50140 | keep-me-signed-in interrupt | benign interrupt, not a failure |
| 50058 | silent sign-in failed | benign; SSO could not complete |

`AuthenticationRequirement` is `singleFactorAuthentication` or `multiFactorAuthentication`;
`AuthenticationDetails` lists each step and whether MFA was "satisfied by claim in the
token", which is what a replayed token looks like.

## Identity Protection risk event types

`RiskEventType` values you will see in `AADUserRiskEvents` and `RiskEventTypes_V2`:
`unfamiliarFeatures`, `anonymizedIPAddress`, `maliciousIPAddress`, `unlikelyTravel`,
`atypicalTravel` (older name), `newCountry`, `leakedCredentials`, `passwordSpray`,
`anomalousToken`, `tokenIssuerAnomaly`, `attackerinTheMiddle`, `suspiciousBrowser`,
`suspiciousAPITraffic`, `suspiciousInboxForwarding`,
`mcasSuspiciousInboxManipulationRules`, `mcasImpossibleTravel`, `riskyIPAddress`,
`adminConfirmedUserCompromised`, `investigationsThreatIntelligence`, `generic`.
`anomalousToken` and `attackerinTheMiddle` are the ones that should end the debate about
whether a session was stolen.

## AiTM and token replay indicators

- Interactive success with `multiFactorAuthentication` from a new IP/ASN within minutes of
  a phishing click, followed by non-interactive sign-ins from that IP with
  `IncomingTokenType == refreshToken` or `primaryRefreshToken`.
- The same `SessionId` (or `UniqueTokenIdentifier` lineage via `OriginalRequestId`) seen
  from two different ASNs.
- `AuthenticationDetails` showing MFA "satisfied by claim in the token" on the attacker's
  sign-ins, with no fresh MFA challenge.
- `AppDisplayName` of `OfficeHome` or `Microsoft Office` for the first attacker sign-in
  (the default resource the AiTM proxy requests), then Exchange Online / Graph.
- A device registration (`AuditLogs` "Register device" / "Add registered owner to device")
  from the attacker IP soon after: they are minting a PRT to outlive session revocation.
- `AADUserRiskEvents` with `anomalousToken` or `attackerinTheMiddle`.
- `UserAgent` that does not match the user's history (Linux Firefox for a Windows Edge user).
- Data access from the attacker IP in `OfficeActivity` (`MailItemsAccessed`,
  `FileDownloaded`, `SearchQueryInitiated`) and `MicrosoftGraphActivityLogs`.

## KQL

```kusto
// Sign-in history for one user with the fields that matter (interactive + non-interactive)
let u = "alice.dev@yourcompany.example";
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d) and UserPrincipalName =~ u
| extend Country = tostring(Location.countryOrRegion), City = tostring(Location.city),
         MfaBy = tostring(parse_json(AuthenticationDetails)[0].authenticationStepResultDetail)
| project TimeGenerated, Type, IPAddress, AutonomousSystemNumber, Country, City, ResultType, ResultDescription,
          AuthenticationRequirement, MfaBy, ConditionalAccessStatus, ClientAppUsed, AppDisplayName,
          UserAgent, SessionId, IncomingTokenType, RiskLevelDuringSignIn, RiskEventTypes_V2
| order by TimeGenerated asc

// Same session ID from more than one ASN (token replay)
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(14d) and isnotempty(SessionId)
| summarize ASNs = make_set(AutonomousSystemNumber), IPs = make_set(IPAddress, 10),
            Users = make_set(UserPrincipalName, 5), First = min(TimeGenerated), Last = max(TimeGenerated)
      by SessionId
| where array_length(ASNs) > 1

// MFA fatigue: bursts of 500121 then a success from the same IP
SigninLogs
| where TimeGenerated > ago(7d) and ResultType in ("500121", "0")
| summarize Denials = countif(ResultType == "500121"), Success = countif(ResultType == "0"),
            FirstDenial = minif(TimeGenerated, ResultType == "500121"),
            FirstSuccess = minif(TimeGenerated, ResultType == "0")
      by UserPrincipalName, IPAddress, bin(TimeGenerated, 30m)
| where Denials >= 5 and Success > 0

// Password spray: one IP, many users, mostly 50126 / 50034
SigninLogs
| where TimeGenerated > ago(24h) and ResultType in ("50126", "50034", "50053")
| summarize Users = dcount(UserPrincipalName), Attempts = count(), Apps = make_set(AppDisplayName, 5)
      by IPAddress, AutonomousSystemNumber, bin(TimeGenerated, 1h)
| where Users >= 10
| order by Users desc

// Legacy authentication successes
SigninLogs
| where TimeGenerated > ago(30d) and ResultType == "0"
| where ClientAppUsed in ("IMAP4", "POP3", "SMTP", "Authenticated SMTP", "Other clients",
                         "Exchange ActiveSync", "MAPI Over HTTP", "Outlook Anywhere", "Exchange Web Services")
| project TimeGenerated, UserPrincipalName, IPAddress, tostring(Location.countryOrRegion), ClientAppUsed,
          UserAgent, AuthenticationRequirement

// OAuth consent grants and app role assignments for a user or by a user
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Consent to application", "Add delegated permission grant",
                          "Add app role assignment grant to user", "Add app role assignment to service principal",
                          "Add service principal", "Add OAuth2PermissionGrant")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), ActorIP = tostring(InitiatedBy.user.ipAddress),
         App = tostring(TargetResources[0].displayName), AppId = tostring(TargetResources[0].id),
         Props = TargetResources[0].modifiedProperties
| mv-apply p = Props on (
    summarize ConsentType = anyif(tostring(p.newValue), p.displayName == "ConsentContext.IsAdminConsent"),
              Permissions = anyif(tostring(p.newValue), p.displayName == "ConsentAction.Permissions"))
| project TimeGenerated, OperationName, Result, Actor, ActorIP, App, AppId, ConsentType, Permissions

// MFA / security info changes (self-service or admin), and device registrations
AuditLogs
| where TimeGenerated > ago(30d)
| where Category in ("UserManagement", "Device") or OperationName has "security info"
| where OperationName in ("User registered security info", "User changed default security info",
    "User deleted security info", "Admin registered security info", "Admin updated security info",
    "Admin deleted security info", "Register device", "Add registered owner to device",
    "Reset password (by admin)", "Change user password", "Reset user password", "Update user")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), ActorIP = tostring(InitiatedBy.user.ipAddress),
         Target = tostring(TargetResources[0].userPrincipalName), Detail = tostring(TargetResources[0].modifiedProperties)
| project TimeGenerated, OperationName, Result, Actor, ActorIP, Target, ResultReason, Detail

// Inbox rules, forwarding, and delegation
OfficeActivity
| where TimeGenerated > ago(30d) and OfficeWorkload == "Exchange"
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule", "UpdateInboxRules",
                      "Set-Mailbox", "Add-MailboxPermission", "Add-MailboxFolderPermission",
                      "Set-MailboxJunkEmailConfiguration", "New-TransportRule", "Set-TransportRule")
| extend P = tostring(Parameters)
| where Operation != "Set-Mailbox" or P has_any ("ForwardingSmtpAddress", "ForwardingAddress", "DeliverToMailboxAndForward")
| project TimeGenerated, UserId, ClientIP, Operation, P
// suspicious rule parameters: ForwardTo, ForwardAsAttachmentTo, RedirectTo, DeleteMessage,
// MoveToFolder (RSS Subscriptions, Archive, Conversation History), MarkAsRead,
// SubjectContainsWords (invoice, payment, password, wire, phish, hacked, suspicious)

// Privilege changes
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in ("Add member to role", "Add eligible member to role",
    "Add member to role in PIM completed (permanent)", "Add member to role in PIM completed (timebound)",
    "Add member to group", "Add owner to group", "Add owner to application", "Add owner to service principal",
    "Update conditional access policy", "Delete conditional access policy", "Add named location",
    "Set federation settings on domain", "Add partner to company")
| extend Actor = tostring(InitiatedBy.user.userPrincipalName), ActorIP = tostring(InitiatedBy.user.ipAddress),
         Target = tostring(TargetResources[0].displayName), TargetUpn = tostring(TargetResources[0].userPrincipalName),
         Role = tostring(TargetResources[1].displayName)
| project TimeGenerated, OperationName, Result, Actor, ActorIP, Target, TargetUpn, Role

// What the attacker session touched (mail and files) from a given IP
OfficeActivity
| where TimeGenerated > ago(14d) and ClientIP == "198.51.100.77"
| summarize Ops = count(), Types = make_set(Operation, 20), First = min(TimeGenerated), Last = max(TimeGenerated)
      by UserId, OfficeWorkload
```

Note on `MailItemsAccessed`: it is present with Purview Audit (Premium) / E5 and is the
only way to say which messages were read. Without it, mailbox reads are "not checkable".

## Risky consent: what to look for

- `ConsentType` `AllPrincipals` (admin consent) for an app nobody recognizes.
- Delegated scopes: `Mail.Read`, `Mail.ReadWrite`, `Mail.Send`, `MailboxSettings.ReadWrite`,
  `Files.ReadWrite.All`, `Sites.Read.All`, `Contacts.Read`, `User.Read.All`,
  `Directory.AccessAsUser.All`, `offline_access` (long-lived refresh token) combined with any of these.
- Multi-tenant app whose publisher is unverified, display name mimics Microsoft or a common tool.
- Consent from an IP the user does not normally use, minutes after a phishing click.
- Service principal created the same day as the consent.

Remove with `Remove-MgOauth2PermissionGrant` (delegated) and by deleting the app role
assignment; disable the service principal (`accountEnabled = false`) if the app is
attacker-controlled; block it tenant-wide with an app consent policy. Export the grant first.

## Containment order and cautions

| Step | How | Caution |
|---|---|---|
| 1. Reset password | Entra portal or `Update-MgUser` / Graph `passwordProfile`; for synced users reset in AD (password writeback or on-prem) | with PTA / federation, resetting only in the cloud does nothing; PHS sync lag is minutes |
| 2. Revoke sessions | `Revoke-MgUserSignInSession` (Graph `revokeSignInSessions`) | invalidates refresh tokens; access tokens remain valid up to ~1 h; PRTs on registered devices re-auth silently unless the device is also removed or CA blocks it |
| 3. Block immediately if sensitive | CA policy: block user (or require compliant device) ; mark user compromised in Identity Protection (forces password change and MFA at next sign-in) | CA evaluates on token issuance; combine with revocation |
| 4. Remove attacker MFA methods and devices | Authentication methods blade; `Remove-MgUserAuthentication*`; delete registered devices from the attacker window | verify the user's real methods through a trusted channel before deleting; re-register with the user on a call |
| 5. Remove consents | see above | export first; check whether other users consented to the same app |
| 6. Remove inbox rules / forwarding / delegation | Exchange admin center or `Remove-InboxRule`, `Set-Mailbox -ForwardingSmtpAddress $null` | rules can hide in the "junk" or Outlook client-only rules; check via `Get-InboxRule -IncludeHidden` |
| 7. Undo privilege changes | remove role members / PIM assignments, restore CA policies from backup, remove federation / partner | if the attacker added themselves as Global Admin, do this before revoking their sessions, or they re-add themselves |
| 8. Disable account | `accountEnabled = false` | last resort for humans; for a shared mailbox, disable sign-in only |
| 9. Tenant-wide | block attacker IPs/ASN via named location; require MFA re-registration for affected users; enable continuous access evaluation | country blocks lock out travelers; scope to the affected apps if possible |

After containment, query both sign-in tables for the user and for the attacker IP over
the next 48 hours. Any success means a device or method survived.
