# Environment customization (edit me)

Fill this in for your tenant. The skill reads it to decide which log store to point queries
at, which identities and networks to treat as background noise, and who signs off on
containment. Keep it short.

## Cloud footprint

| Cloud | Org / tenant ID | Accounts, subscriptions, projects that matter | Security / forensic account |
|---|---|---|---|
| AWS | o-xxxxxxxxxx | `123456789012` (prod), `210987654321` (dev), `<log-archive-account>` | `<forensic-account-id>` |
| Azure | `<tenant-id>` | `<prod-subscription-id>`, `<dev-subscription-id>` | `<forensic-subscription-id>` |
| GCP | `<org-id>` | `yourcompany-prod`, `yourcompany-dev` | `yourcompany-forensics` |

## Where the logs live (changes which query examples apply)

| Source | Location | Retention | Data-plane events on? |
|---|---|---|---|
| AWS CloudTrail (org trail) | S3 `s3://yourcompany-cloudtrail/AWSLogs/o-xxxx/` ; Athena table `cloudtrail_logs` in `<athena-db>` ; CloudTrail Lake event data store `<name>` | 400 days | S3: prod buckets only ; Lambda: no |
| AWS GuardDuty | delegated admin account `<id>` ; findings exported to `<s3-bucket>` | 90 days | n/a |
| AWS VPC Flow Logs | CloudWatch Logs group `/vpc/flow` or S3 `<bucket>` | 30 days | n/a |
| Azure Activity Log | Log Analytics workspace `<workspace-name>` (`AzureActivity`) | 90 days | n/a |
| Entra ID sign-in / audit | same workspace (`SigninLogs`, `AuditLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`) | 30 days (raise to 90+) | n/a |
| Azure resource diagnostics | `AzureDiagnostics` or resource-specific tables (`AZKVAuditLogs`, `StorageBlobLogs`) | 30 days | Key Vault: yes ; Storage: `<yes/no>` |
| GCP Cloud Audit Logs | `_Default` bucket in `yourcompany-prod` ; aggregated sink to `<log-bucket-or-bq-dataset>` | 30 days default (`_Required` 400 days) | Data Access: `<yes/no per service>` |
| SIEM | `<siem-url>` (`<siem-product>`) ; index/table names: `<...>` | 365 days | copy of the above |

## Known-good automation (do not chase, but do verify)

| Identity | Purpose | Expected source IPs / ranges | Expected user agents |
|---|---|---|---|
| `arn:aws:iam::123456789012:role/ci-deploy` | GitHub Actions deploys | GitHub Actions ranges (verify against published list) | `aws-sdk-go/...` |
| `arn:aws:iam::123456789012:role/aws-service-role/...` | AWS service-linked roles | AWS service names | AWS service names |
| `<terraform-sp-app-id>` (Azure SP) | Terraform Cloud runs | `<terraform-cloud-ranges>` | `Go-http-client/...` |
| `terraform@yourcompany-prod.iam.gserviceaccount.com` | Terraform | `<ranges>` | `Terraform/...` |
| Corporate egress / VPN | human admins | `203.0.113.0/24`, `198.51.100.0/24` | browsers, `aws-cli/2.*`, `az-cli/*`, `gcloud/*` |

Anything from a human principal that does not come from these ranges deserves a look.

## High-risk event overrides

The summarizer ships with a default list (see `DEFAULT_HIGH_RISK` in
`scripts/cloudtrail_summarize.py`). To replace it, keep a file of `EventName,reason` lines
and pass `--high-risk references/high-risk-events.txt`. To add a few without replacing,
use `--extra-risk GetObject,ListBuckets`. Typical local additions:

- `GetObject` on `<crown-jewel-bucket>` (only useful when S3 data events are on)
- `Invoke` for `<bedrock or sagemaker>` if model abuse is a concern
- `CreateGrant` / `RetireGrant` if KMS grants are part of your architecture

## Thresholds

| Setting | Default | Meaning |
|---|---|---|
| Investigation window start | trigger minus 7 days | extend to 30 for a long-lived key |
| Recon burst | >= 20 list/describe/get-account events by one identity in 10 minutes | flag as recon phase |
| Secret read burst | >= 5 `GetSecretValue` / `AccessSecretVersion` / `SecretGet` in 5 minutes | treat as collection |
| "New" source IP | not seen for that identity in the prior 30 days | pivot on it |

## Containment authority

| Action | Who approves | Where recorded |
|---|---|---|
| Deactivate an IAM user key / disable a user | on-call IR lead | `<ticket-system>` |
| Revoke role sessions / attach deny to a shared role | IR lead + platform owner | incident channel `#<channel>` |
| SCP / Azure Policy / Org Policy deny | CISO delegate + platform lead | change record |
| Snapshot and share to forensic account | IR lead | incident channel |
| Restore logging / re-enable GuardDuty | platform on-call | change record |

## Escalation

- Cloud platform on-call: `<pager-or-channel>`
- Legal / privacy (for data exposure decisions): `<contact>`
- Cloud provider support / TAM: `<contact>` (ask about abuse-team engagement for attacker infra)
