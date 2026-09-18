# GCP investigation reference

Contents: log sources; identity kinds; high-signal methods by phase; Logging query
language examples; BigQuery over exported logs; preservation; containment.

Accurate as of September 2026 for Cloud Audit Logs field names (`protoPayload.*`) and the
method names listed. GCP method names are stable but service-specific; when unsure, filter
by `protoPayload.serviceName` and look at what appears.

## Log sources and what each answers

| Source | Where | Answers | Notes |
|---|---|---|---|
| Cloud Audit Logs: Admin Activity | `logName = projects/<p>/logs/cloudaudit.googleapis.com%2Factivity` | control-plane writes: IAM changes, resource create/delete, SA key creation | always on, cannot be disabled, 400-day retention in `_Required` bucket |
| Cloud Audit Logs: Data Access | `.../cloudaudit.googleapis.com%2Fdata_access` | reads and data-plane calls (GCS object gets, Secret Manager access, BigQuery queries) | off by default except BigQuery; must be enabled per service in IAM audit config. Without it, "was the object read" is unanswerable |
| Cloud Audit Logs: System Event | `.../cloudaudit.googleapis.com%2Fsystem_event` | Google-initiated changes (live migration, auto-restart) | rarely relevant |
| Cloud Audit Logs: Policy Denied | `.../cloudaudit.googleapis.com%2Fpolicy` | VPC Service Controls denials | exfil attempts blocked by perimeters |
| Access Transparency | `.../cloudaudit.googleapis.com%2Faccess_transparency` | Google staff access | requires support tier |
| VPC Flow Logs | `compute.googleapis.com/vpc_flows` | network conversations | sampled; enable per subnet |
| Firewall Rules Logging | `compute.googleapis.com/firewall` | allowed/denied connections per rule | enable per rule |
| Cloud DNS logging | `dns.googleapis.com/dns_queries` | queries from VMs | enable per policy |
| GKE audit | `logName` with `cloudaudit.googleapis.com%2Factivity` and `resource.type = k8s_cluster` | Kubernetes API calls | on for GKE control plane |
| Security Command Center | SCC findings (Event Threat Detection, Container Threat Detection) | managed detections such as anomalous IAM grants, SA key created, log sink deleted, crypto-mining | still go to the raw log |
| Google Workspace / Cloud Identity | Admin console audit (Login, Admin, OAuth token), also exportable to Cloud Logging | user sign-ins, OAuth grants, admin changes | the identity side; `identity-threat-investigation` for user sign-in analysis |

## Identity kinds

| `protoPayload.authenticationInfo.principalEmail` looks like | Kind | Notes |
|---|---|---|
| `alice@yourcompany.example` | Workspace / Cloud Identity user | check Workspace login audit for the session |
| `<name>@<project>.iam.gserviceaccount.com` | service account | key-based or impersonated; look at `serviceAccountKeyName` and `serviceAccountDelegationInfo` |
| `<number>-compute@developer.gserviceaccount.com` | default Compute SA | often over-privileged (Editor); metadata-server token theft from a VM |
| `service-<number>@gcp-sa-<service>.iam.gserviceaccount.com` | Google-managed service agent | expected for platform operations |
| `principal://iam.googleapis.com/locations/global/workloadIdentityPools/...` | workload identity federation | external identity (GitHub Actions, AWS, Azure) mapped in; check the pool's attribute conditions |

`protoPayload.authenticationInfo.serviceAccountKeyName` tells you a user-managed key was
used (vs. an attached identity or impersonation). `serviceAccountDelegationInfo` lists the
impersonation chain: the first principal is who actually held the credential.

## High-signal methods by phase

**Initial access and credentials**
- `google.iam.admin.v1.CreateServiceAccountKey` (`iam.googleapis.com`): new long-lived credential
- `google.iam.admin.v1.CreateServiceAccount`
- `google.iam.credentials.v1.IAMCredentials.GenerateAccessToken`, `GenerateIdToken`, `SignBlob`, `SignJwt` (`iamcredentials.googleapis.com`): impersonation; the caller is in `authenticationInfo.principalEmail`, the target SA in `protoPayload.resourceName`
- Workspace Login audit: `login_success`, `login_failure`, `suspicious_login`, `2sv_disable`

**Discovery**
- `google.iam.v1.IAMPolicy.GetIamPolicy` / `GetIamPolicy` across many resources
- `google.cloud.resourcemanager.v3.Projects.ListProjects`, `SearchProjects`
- `storage.buckets.list`, `storage.objects.list` (Data Access log)
- `google.iam.admin.v1.ListServiceAccounts`, `ListServiceAccountKeys`
- `compute.instances.list`, `compute.firewalls.list`, `compute.snapshots.list`
- `google.cloud.secretmanager.v1.SecretManagerService.ListSecrets`
- `google.logging.v2.ConfigServiceV2.ListSinks` (checking where logs go)

**Privilege escalation and persistence**
- `SetIamPolicy` on `cloudresourcemanager.googleapis.com` (project / folder / org) with
  `protoPayload.serviceData.policyDelta.bindingDeltas.action = "ADD"`; roles to watch:
  `roles/owner`, `roles/editor`, `roles/iam.serviceAccountTokenCreator`,
  `roles/iam.serviceAccountKeyAdmin`, `roles/iam.securityAdmin`,
  `roles/resourcemanager.organizationAdmin`, `roles/logging.admin`
- `google.iam.admin.v1.SetIAMPolicy` on a service account (granting `serviceAccountUser` or `TokenCreator` on a privileged SA)
- `google.iam.admin.v1.CreateRole`, `UpdateRole` (custom roles with `*` permissions)
- `compute.instances.setMetadata`, `compute.projects.setCommonInstanceMetadata` (SSH keys, startup scripts)
- `compute.instances.insert` with an attached SA and `cloud-platform` scope
- `google.cloud.functions.v2.FunctionService.CreateFunction` / `UpdateFunction`, Cloud Run
  `google.cloud.run.v1.Services.CreateService`, Cloud Scheduler `CreateJob` (scheduled persistence)
- `google.iam.v1.WorkloadIdentityPools.CreateWorkloadIdentityPool` / `CreateWorkloadIdentityPoolProvider` (external federation backdoor)
- Workspace Admin audit: `ASSIGN_ROLE`, `CREATE_ROLE`, `ADD_PRIVILEGE`, domain-wide delegation `AUTHORIZE_API_CLIENT_ACCESS`

**Defense evasion**
- `google.logging.v2.ConfigServiceV2.DeleteSink`, `UpdateSink` (redirecting exports)
- `google.logging.v2.ConfigServiceV2.CreateExclusion`, `UpdateExclusion` (dropping logs), `DeleteBucket` / `UpdateBucket` on log buckets
- `SetIamPolicy` on the org with `roles/logging.admin` or removing SCC roles
- `google.cloud.securitycenter.v1.SecurityCenter.UpdateFinding` (marking findings inactive), `SetMute`
- `compute.firewalls.insert` / `patch` opening `0.0.0.0/0`, `compute.firewalls.delete`
- `google.cloud.orgpolicy.v2.OrgPolicy.DeletePolicy` / `UpdatePolicy` (removing `iam.disableServiceAccountKeyCreation`, `compute.vmExternalIpAccess`, `storage.publicAccessPrevention`)
- `google.cloud.accesscontextmanager.v1.AccessContextManager.DeleteServicePerimeter` / `UpdateServicePerimeter`

**Collection and exfiltration**
- `google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion` (Data Access log)
- `Decrypt` on `cloudkms.googleapis.com` (Data Access log)
- `storage.objects.get` in volume (Data Access log), `storage.setIamPermissions` with `allUsers` / `allAuthenticatedUsers`
- `storage.buckets.update` (public access prevention off, lifecycle changes)
- `google.cloud.bigquery.v2.JobService.InsertJob` with `jobConfiguration.extract` (table export to GCS) or `query` with a large `totalBilledBytes`; `google.cloud.bigquery.v2.TableService.InsertTable` in another project
- `compute.disks.createSnapshot`, `compute.snapshots.setIamPolicy`, `compute.images.insert` + `compute.images.setIamPolicy` (share to an external project)
- `compute.instances.getSerialPortOutput`, `compute.instances.getGuestAttributes`
- Workspace: `DOWNLOAD` events in Drive audit, `MAIL_FORWARDING` / `EMAIL_FORWARDING_OUT_OF_DOMAIN` in user settings

## Logging query language examples

Use in Logs Explorer or `gcloud logging read '<filter>' --project <p> --freshness=7d`.
Set the time range in the UI or with `timestamp >= "2026-09-07T00:00:00Z"`.

```
-- Everything one principal did (Admin Activity + Data Access)
logName:("cloudaudit.googleapis.com%2Factivity" OR "cloudaudit.googleapis.com%2Fdata_access")
protoPayload.authenticationInfo.principalEmail="deploy-sa@yourcompany-prod.iam.gserviceaccount.com"
timestamp >= "2026-09-07T00:00:00Z"

-- Same, but only from an IP outside the expected ranges (note: no NOT-in-CIDR; list the good ranges)
protoPayload.authenticationInfo.principalEmail="deploy-sa@yourcompany-prod.iam.gserviceaccount.com"
NOT protoPayload.requestMetadata.callerIp:"203.0.113."
NOT protoPayload.requestMetadata.callerIp:"198.51.100."

-- IAM bindings added, with the role and member
protoPayload.methodName="SetIamPolicy"
protoPayload.serviceData.policyDelta.bindingDeltas.action="ADD"
-- narrow to dangerous roles
protoPayload.serviceData.policyDelta.bindingDeltas.role=("roles/owner" OR "roles/editor" OR "roles/iam.serviceAccountTokenCreator" OR "roles/iam.serviceAccountKeyAdmin")

-- Service account keys created
protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"

-- Impersonation: who minted tokens for which SA
protoPayload.serviceName="iamcredentials.googleapis.com"
protoPayload.methodName=("GenerateAccessToken" OR "GenerateIdToken" OR "SignBlob" OR "SignJwt")

-- Calls made with a user-managed SA key (vs. attached identity)
protoPayload.authenticationInfo.serviceAccountKeyName:"keys/"

-- Log sink and exclusion tampering
protoPayload.methodName=("google.logging.v2.ConfigServiceV2.DeleteSink" OR "google.logging.v2.ConfigServiceV2.UpdateSink" OR "google.logging.v2.ConfigServiceV2.CreateExclusion" OR "google.logging.v2.ConfigServiceV2.UpdateExclusion")

-- Secret reads (requires Data Access logs for Secret Manager)
protoPayload.serviceName="secretmanager.googleapis.com"
protoPayload.methodName="google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"

-- Bucket made public
protoPayload.methodName="storage.setIamPermissions"
protoPayload.serviceData.policyDelta.bindingDeltas.member=("allUsers" OR "allAuthenticatedUsers")

-- Metadata / startup-script changes on VMs
protoPayload.methodName=("v1.compute.instances.setMetadata" OR "v1.compute.projects.setCommonInstanceMetadata" OR "beta.compute.instances.setMetadata")

-- Permission-denied bursts (recon)
protoPayload.status.code=7
protoPayload.authenticationInfo.principalEmail="suspect@yourcompany.example"

-- BigQuery extract jobs (table export)
protoPayload.serviceName="bigquery.googleapis.com"
protoPayload.methodName="google.cloud.bigquery.v2.JobService.InsertJob"
protoPayload.metadata.jobInsertion.job.jobConfig.type="EXTRACT"
```

Older BigQuery audit records use `protoPayload.serviceData.jobInsertRequest`; the
`metadata.jobInsertion` form is the current BigQueryAuditMetadata. Query both when in
doubt.

## BigQuery over an exported log sink

If an aggregated sink writes to BigQuery (table names like
`cloudaudit_googleapis_com_activity`), the same questions become SQL. `protopayload_auditlog`
is the column; nested fields are accessed with dots. See `siem-query-authoring`
(`references/sql.md`) for general SQL patterns.

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail AS principal,
       protopayload_auditlog.methodName, protopayload_auditlog.resourceName,
       protopayload_auditlog.requestMetadata.callerIp AS ip,
       protopayload_auditlog.requestMetadata.callerSuppliedUserAgent AS ua,
       protopayload_auditlog.status.code AS status
FROM `yourcompany-logs.audit.cloudaudit_googleapis_com_activity`
WHERE timestamp BETWEEN '2026-09-07' AND '2026-09-15'
  AND protopayload_auditlog.authenticationInfo.principalEmail = 'deploy-sa@yourcompany-prod.iam.gserviceaccount.com'
ORDER BY timestamp;
```

## Preservation

- **Audit logs:** Admin Activity logs cannot be turned off and live 400 days in `_Required`,
  but Data Access logs go to `_Default` (30 days) and can be excluded. Check
  `ListExclusions` and sink state first, then export the window (`gcloud logging copy` to
  a log bucket in the forensic project, or a one-off sink to GCS with retention lock).
- **Compute:** `gcloud compute disks snapshot` every attached disk (label with the case
  ID); share the snapshot to the forensic project by granting `roles/compute.storageAdmin`
  on it or by creating an image. Isolate the VM with a network tag that matches a deny-all
  firewall rule rather than stopping it. Remove the attached SA's roles (not the SA) to stop
  metadata-server token use.
- **Serverless:** download the Cloud Function / Cloud Run source (the deployment bucket or
  `gcloud functions describe` for the source location) and environment variables.
- **IAM state:** `gcloud projects get-iam-policy`, `gcloud iam service-accounts keys list`
  for every SA, org policy constraints, and workload identity pool providers, at the start.
- **Workspace:** export Login, Admin, OAuth token, and Drive audit logs for the users
  involved; Workspace audit retention is 6 months.

## Containment

| Action | Command / console | Blast radius and cautions |
|---|---|---|
| Disable a service account key | `gcloud iam service-accounts keys disable <key-id> --iam-account <sa>` | reversible; delete after closure. Anything using the key fails |
| Disable a service account | `gcloud iam service-accounts disable <sa>` | attached workloads and impersonators lose access immediately; prefer key-level or binding-level first if the SA is shared |
| Remove an IAM binding | `gcloud projects remove-iam-policy-binding` (also folder / org) | check every level of the hierarchy; a binding at folder or org scope survives project-level cleanup |
| Revoke a user's sessions / OAuth tokens | Workspace Admin console: sign out user, reset sign-in cookies, revoke app tokens; reset password; re-enroll 2SV | `identity-threat-investigation` covers the order of operations |
| Block public exposure | `storage.publicAccessPrevention` org policy enforced; remove `allUsers` bindings | org policy applies to new and existing buckets |
| Stop metadata-server credential use on a VM | remove roles from the attached SA; or `gcloud compute instances set-service-account --no-service-account` (requires stop) | changing the SA needs a stop; removing roles does not |
| Prevent recurrence | org policies `iam.disableServiceAccountKeyCreation`, `iam.disableServiceAccountKeyUpload`, `iam.automaticIamGrantsForDefaultServiceAccounts`, `compute.vmExternalIpAccess`; VPC Service Controls perimeter around storage / BigQuery / Secret Manager | org policy changes can break legitimate key-based integrations; inventory them first |
| Domain-wide delegation backdoor | Workspace Admin: API controls, remove the client ID | verify with the owning team; DWD is legitimate for some integrations |

After containment, re-run the principal filter for the contained identities. Any
`status.code` other than 7 (`PERMISSION_DENIED`) or 16 (`UNAUTHENTICATED`) on a write
method means a credential was missed.
