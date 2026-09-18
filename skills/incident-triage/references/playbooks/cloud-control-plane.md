# Triage playbook: cloud control-plane alerts

Covers: AWS GuardDuty / CloudTrail-based detections, Azure Defender for Cloud and Activity
Log alerts, GCP Security Command Center findings, and custom SIEM rules on IAM, logging,
storage-policy, and compute changes.

## Questions to answer
1. Which **identity** did it (user, role, service principal, service account, key ID) and from where (IP, user agent)?
2. Was the identity a human, a pipeline, or a service? Is that identity expected to do this action at all?
3. Did the action **succeed**? A wave of AccessDenied errors is reconnaissance; one success is the event.
4. What is the blast radius of the resource touched (account/subscription/project criticality, data classification)?
5. Is there a deployment, pipeline run, or change ticket for the same resource in the same window?

## Data to pull
- The raw event(s): CloudTrail record / Azure Activity Log entry / GCP audit log with full request parameters.
- All events by the same identity for the previous 24 hours (what did it do before and after?).
- Source IP and user agent history for that identity over 30 days; is this a new one?
- Credential provenance: access key age, role assumption chain, OIDC federation source, MFA on the session.
- IaC / pipeline logs (Terraform, CloudFormation, ARM, GitHub Actions) for the resource around the time.
- Resource state now: policy contents, public access flags, new users/keys/roles, logging status.

## Benign explanation checklist
- [ ] Action was performed by a CI/CD role from the pipeline's known egress IP with a matching run ID.
- [ ] Named engineer with a change ticket, working from corporate VPN/SSO with MFA.
- [ ] Automated drift-remediation, autoscaling, backup, or security-tool activity (check the principal name).
- [ ] Vendor integration or SaaS scanner with a documented cross-account role.
- [ ] Alert fired on a read-only or describe action that is normal for the identity's role.
- [ ] Sandbox / dev account with no production data (still a hygiene item).

## True-positive indicators
- New access keys or credentials created for an existing user, especially by a different identity.
- Logging or monitoring disabled or altered (trail stopped, diagnostic settings deleted, audit sinks removed).
- Storage made public, bucket/blob policies opened, snapshot shared to another account.
- Privilege escalation paths: policy attached to self, role trust policy widened, new admin role assignment.
- Actions from a residential/anonymizer IP, from an unusual region, or with an unusual SDK/user agent.
- Secrets manager / key vault bulk reads; mass enumeration followed by a targeted write.
- Long-lived key used after a period of dormancy, or a key used from two continents in an hour.

## Scoping questions
- What other accounts/subscriptions/projects can this identity reach (trust relationships, org roles)?
- Were resources created that persist (users, keys, roles, functions, instances, OAuth apps)?
- Did the identity access data (object gets, database exports, snapshot copies)? How much?
- Is the credential still valid right now?

## Escalation criteria
- Escalate immediately: successful privilege escalation, logging tampering, public exposure of sensitive data,
  credential creation by an unrecognised identity, or activity in a production account from an anonymizer.
- Escalate the same shift: unexplained successful write actions by a human identity with no ticket.
- Rotating keys, attaching deny policies, or applying SCPs/Azure Policy denies can break production;
  follow the approval and rollback guidance in `environment.md` and `cloud-incident-investigation`.

## Hand-offs
- Full investigation and containment: `cloud-incident-investigation` (per-cloud query examples live there).
- Federated identity or IdP compromise upstream: `identity-threat-investigation`.
- Query building over CloudTrail/Activity logs: `siem-query-authoring`.
