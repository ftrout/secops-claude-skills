# Okta investigation reference

Contents: System Log shape; event types by phase; behaviors and threat fields; System Log
filter examples; containment order with cautions.

Accurate as of September 2026 for Okta Identity Engine tenants. Classic Engine tenants
share most event types but lack some of the authenticator-specific ones.

## The System Log record

Every event is JSON with the same envelope. Fields that matter:

| Field | Meaning |
|---|---|
| `eventType` | dotted name, e.g. `user.session.start` |
| `published` | ISO 8601 UTC timestamp |
| `actor.alternateId`, `actor.displayName`, `actor.type` | who acted (`User`, `SystemPrincipal`, `PublicClientApp`) |
| `client.ipAddress`, `client.geographicalContext.{city,state,country}`, `client.userAgent.rawUserAgent`, `client.device`, `client.zone` | where from |
| `outcome.result` (`SUCCESS`, `FAILURE`, `SKIPPED`, `ALLOW`, `DENY`, `CHALLENGE`), `outcome.reason` | result and why |
| `target[]` (`type`, `alternateId`, `displayName`) | what was acted on: user, app, factor, policy, rule |
| `authenticationContext.externalSessionId` | the Okta session ID: the pivot for "everything this session did" |
| `authenticationContext.authenticationProvider`, `credentialType` | password, factor, federation |
| `securityContext.asNumber`, `asOrg`, `isp`, `domain`, `isProxy` | network enrichment; `isProxy` true is worth a look |
| `debugContext.debugData.risk` | risk level and reasons (Identity Threat Protection / risk scoring) |
| `debugContext.debugData.behaviors` | `New IP`, `New Device`, `New Country`, `New State`, `New Geo-Location`, `Velocity` each `POSITIVE` / `NEGATIVE` |
| `debugContext.debugData.threatSuspected` | `true` when ThreatInsight flagged the IP |
| `debugContext.debugData.dtHash` | device token hash; a stable browser identifier |
| `debugContext.debugData.factor` / `authnRequestId` | which authenticator was used |
| `transaction.id` | groups events from one HTTP transaction |

## Event types by phase

**Authentication and session**
- `user.session.start` (primary auth success or failure; `outcome.reason` such as `INVALID_CREDENTIALS`, `LOCKED_OUT`, `VERIFICATION_ERROR`)
- `user.authentication.auth_via_mfa` (factor verified; `target` names the factor)
- `user.authentication.sso` (app launch through an existing session; the attacker's ongoing use looks like this)
- `user.session.end`, `user.session.clear` (sessions revoked)
- `user.authentication.auth_via_richclient`, `user.authentication.auth_via_IDP` (federated inbound)
- `policy.evaluate_sign_on` (sign-on policy decision; `outcome.result` `ALLOW`/`DENY`/`CHALLENGE`)
- `user.session.access_admin_app` (Admin Console opened: a strong signal when the user is not an admin by day)
- `security.threat.detected`, `security.request.blocked` (ThreatInsight)
- `user.account.report_suspicious_activity_by_enduser` (user clicked "report" on the new-sign-in email)

**MFA and account changes**
- `user.mfa.factor.activate`, `user.mfa.factor.deactivate`, `user.mfa.factor.reset_all`, `user.mfa.factor.update`, `user.mfa.factor.suspend`, `user.mfa.factor.unsuspend`
- `user.account.reset_password`, `user.account.update_password`, `user.account.update_primary_email`, `user.account.update_secondary_email`
- `user.account.lock`, `user.account.unlock`, `user.account.unlock_by_admin`
- `user.lifecycle.create`, `.activate`, `.deactivate`, `.suspend`, `.unsuspend`, `.delete.initiated`
- `user.account.privilege.grant`, `user.account.privilege.revoke` (admin roles)
- `group.user_membership.add`, `group.user_membership.remove` (watch groups that grant admin or app access)
- `application.user_membership.add`, `application.user_membership.remove`

**Admin, policy, and tenant-level persistence**
- `system.api_token.create`, `system.api_token.revoke` (SSWS API tokens; a new one from a compromised admin is persistence)
- `app.oauth2.client.lifecycle.create`, `application.lifecycle.create`, `application.lifecycle.update`, `app.oauth2.as.lifecycle.update` (new OAuth clients / app integrations)
- `system.idp.lifecycle.create`, `system.idp.lifecycle.update`, `system.idp.key.create` (a new inbound IdP or routing rule is a federated backdoor)
- `policy.lifecycle.create` / `.update` / `.delete`, `policy.rule.add` / `.update` / `.deactivate` / `.delete` (sign-on, MFA enrollment, password policies weakened)
- `zone.create`, `zone.update`, `zone.deactivate` (network zones; an attacker adds their IP to a trusted zone)
- `system.agent.ad.create`, `system.agent.ad.update` (AD agents), `system.org.rate_limit.violation`
- `user.session.impersonation.initiate`, `.grant`, `.extend`, `.end` (Okta Support impersonation; verify a support case exists)
- `system.email.account_lockout.sent`, `system.email.mfa_enroll_notification.sent` (evidence the user was notified)
- `workflow.*` and `system.org.*` for Workflows and org settings changes

## Attack patterns in Okta terms

| Pattern | What you see |
|---|---|
| Password spray | many `user.session.start` `FAILURE` with `INVALID_CREDENTIALS` across users from one IP/ASN; `security.threat.detected` if ThreatInsight caught it |
| MFA fatigue | repeated `user.authentication.auth_via_mfa` `FAILURE` (push denied / timeout) then `SUCCESS` from the same `client.ipAddress`; Okta Verify number challenge, when enforced, defeats this |
| AiTM / session theft | `user.session.start` `SUCCESS` with `behaviors` `New IP`, `New Device`, `New Country` `POSITIVE`, then `user.authentication.sso` events from a different IP with the same `externalSessionId`; `dtHash` differs from the user's history |
| Factor takeover | `user.mfa.factor.activate` (new phone / authenticator) from the attacker IP shortly after first access; `user.mfa.factor.reset_all` by an admin actor you did not expect |
| Admin persistence | `user.account.privilege.grant`, `system.api_token.create`, `system.idp.lifecycle.create`, `zone.update`, `policy.rule.update` |
| Help-desk social engineering | `user.mfa.factor.reset_all` or `user.account.reset_password` by a help-desk actor, followed immediately by enrollment from a new geography |
| Support impersonation abuse | `user.session.impersonation.*` without a matching support case; confirm with Okta |

## System Log filter examples

Use in Admin Console > Reports > System Log (advanced filter) or the API
`GET /api/v1/logs?since=...&filter=...`. Syntax is SCIM-style.

```
# Everything one user did (as actor or target)
actor.alternateId eq "alice.dev@yourcompany.example" or target.alternateId eq "alice.dev@yourcompany.example"

# Sign-in failures from one IP
eventType eq "user.session.start" and outcome.result eq "FAILURE" and client.ipAddress eq "192.0.2.7"

# Successful sign-ins flagged with new-behavior signals
eventType eq "user.session.start" and outcome.result eq "SUCCESS" and debugContext.debugData.behaviors co "POSITIVE"

# ThreatInsight and proxy-sourced events
eventType sw "security." or securityContext.isProxy eq true

# MFA factor enrollments and resets
eventType eq "user.mfa.factor.activate" or eventType eq "user.mfa.factor.reset_all" or eventType eq "user.mfa.factor.deactivate"

# Admin role grants, API tokens, IdPs, zones, policy rules
eventType eq "user.account.privilege.grant" or eventType sw "system.api_token" or eventType sw "system.idp" or eventType sw "zone." or eventType sw "policy.rule"

# Everything a session did
authenticationContext.externalSessionId eq "<session-id>"

# Impersonation
eventType sw "user.session.impersonation"
```

For a CSV export, use the System Log "Download CSV" or the API with `limit=1000` and
follow `Link: rel="next"`. Feed the CSV to `signin_analyzer.py` with
`--col user=actor.alternateId --col timestamp=published --col ip=client.ipAddress
--col country=client.geographicalContext.country --col result=outcome.result
--col mfa=outcome.reason --col user_agent=client.userAgent.rawUserAgent`.

## Containment order and cautions

| Step | How | Caution |
|---|---|---|
| 1. Reset password | user > "Reset password" (or expire); for AD-sourced users reset in AD | delegated-auth users: the cloud reset does not change AD |
| 2. Clear sessions | user > "Clear user sessions" (API `DELETE /api/v1/users/{id}/sessions`) | revokes Okta sessions; downstream app sessions (Google, M365, AWS) persist until those expire or are revoked there |
| 3. Revoke app tokens | user > "Revoke all OAuth / OIDC tokens" (API `/users/{id}/clients/{clientId}/tokens`) ; for AWS / M365 revoke on their side | |
| 4. Reset factors | "Reset multifactor" for the attacker-added factor only if you can tell them apart (by `published` time and IP); otherwise reset all and re-enroll with the user on a verified call | resetting all leaves the user unable to sign in until re-enrolled |
| 5. Suspend if needed | "Suspend" preserves the account and its assignments; "Deactivate" removes app assignments and can trigger deprovisioning | deactivation is destructive for SCIM-provisioned apps |
| 6. Remove persistence | revoke admin roles, delete API tokens, remove IdPs and routing rules, revert zones and policy rules, delete unknown OAuth clients | export the System Log entries first |
| 7. Block network | add attacker IPs/ASN to a blocked network zone; enable ThreatInsight "block" mode | blocking a residential ISP range hurts real users |
| 8. Harden | require phishing-resistant authenticators (FastPass, FIDO2) for admins; number-challenge on Okta Verify push; admin session limits; re-authentication for Admin Console | |

Verify with the session-ID filter above: no new events should appear for the old
`externalSessionId`, and new `user.session.start` events for the user should carry your
expected geography.
