# AWS investigation reference

Contents: log sources; identity types; high-signal events by phase; Athena SQL for
CloudTrail; CloudTrail Lake and other query paths; preservation; containment.

Accurate as of September 2026 against the CloudTrail event record format (eventVersion
1.09/1.10). Event names change rarely, but verify anything you have not seen before in the
AWS API reference for the service.

## Log sources and what each answers

| Source | Answers | Where it lives | Notes |
|---|---|---|---|
| CloudTrail management events | who called which control-plane API, from where, with what result | org/account trail -> S3 (`AWSLogs/<account>/CloudTrail/<region>/YYYY/MM/DD/*.json.gz`), CloudTrail Lake, Event history (90 days, console) | on by default for Event history only; a trail must exist for S3 delivery. Global services (IAM, STS, signin) log to one region (`us-east-1`) unless the trail is multi-region |
| CloudTrail data events | S3 object reads/writes, Lambda invokes, DynamoDB item ops, EBS direct APIs | same trail, must be enabled per resource type | off by default and high volume. Without them, "was the data read" is unanswerable from CloudTrail |
| CloudTrail Insights | API call-rate and error-rate anomalies | trail with Insights on | optional; useful to spot recon bursts |
| GuardDuty | managed detections (credential exfil, crypto-mining, recon, anomalous API use), findings carry the actor identity and IP | GuardDuty console / delegated admin, Security Hub, EventBridge | findings reference CloudTrail events; still go to the raw log |
| IAM credential report and Access Advisor | key age, last used date and service | IAM console / `GenerateCredentialReport` | "last used" granularity is service-level and can lag |
| IAM Access Analyzer | resources shared outside the zone of trust (buckets, roles, KMS keys, snapshots) | Access Analyzer | run it after the incident to find persistence via resource policies |
| AWS Config | resource configuration history and diffs | Config timeline, aggregator | shows what a policy looked like before and after `PutBucketPolicy` |
| VPC Flow Logs | network conversations for instances/ENIs (5-tuple, bytes, accept/reject) | CloudWatch Logs or S3 | no payload; useful for exfil volume and C2 beacons from compromised compute |
| S3 server access logs | object-level requests including from anonymous principals | target bucket | best-effort delivery; complements data events |
| Route 53 Resolver query logs | DNS queries from VPCs | CloudWatch Logs / S3 / Kinesis | C2 domain lookups from compromised compute |
| ELB / CloudFront access logs | HTTP requests to public apps | S3 | SSRF hunting (requests to `169.254.169.254` patterns in URLs) |
| CloudWatch Logs | application, Lambda, SSM session and command output | log groups | attacker-run SSM `SendCommand` output lands here if configured |
| EKS control plane audit | Kubernetes API calls | CloudWatch Logs `/aws/eks/<cluster>/cluster` | must be enabled |

## `userIdentity.type` values

| Type | Meaning | Pivot on |
|---|---|---|
| `Root` | account root user | any use is notable; console login without MFA is critical |
| `IAMUser` | long-lived user; `accessKeyId` starting `AKIA` is a permanent key, `ASIA` a temporary one | `userName`, `accessKeyId` |
| `AssumedRole` | STS session; `arn` is `assumed-role/<RoleName>/<SessionName>`; `sessionContext.sessionIssuer.arn` is the role | role name, session name, `sessionContext.attributes.mfaAuthenticated` |
| `FederatedUser` | `GetFederationToken` session | `sessionContext.sessionIssuer` |
| `SAMLUser` / `WebIdentityUser` | seen on `AssumeRoleWithSAML` / `AssumeRoleWithWebIdentity` calls | `userName`, `identityProvider` |
| `AWSService` | an AWS service acting on your behalf | `invokedBy` |
| `AWSAccount` | a principal from another account | `accountId` (is it yours?) |
| `Directory`, `Unknown` | rare | inspect the raw record |

The session name in `AssumedRole` ARNs is attacker-chosen. Do not trust `ops` or
`terraform` as evidence of legitimacy.

## High-signal events by phase

Only events I am confident exist under these names. `eventSource` is given so you can
scope queries.

**Initial access and sign-in** (`signin.amazonaws.com`, `sts.amazonaws.com`)
- `ConsoleLogin` with `additionalEventData.MFAUsed = No`, especially for `Root`
- `ConsoleLogin` failures in volume (password spray), then one success
- `GetCallerIdentity` as the first call from a new IP or user agent (the attacker's "whoami")
- `AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity` from an unexpected IdP or IP
- `GetSessionToken`, `GetFederationToken` minting further credentials

**Discovery** (`iam.amazonaws.com`, `s3.amazonaws.com`, `ec2.amazonaws.com`, others)
- `GetAccountAuthorizationDetails`, `ListUsers`, `ListRoles`, `ListAccessKeys`,
  `ListAttachedUserPolicies`, `ListAttachedRolePolicies`, `GetPolicyVersion`
- `ListBuckets`, `GetBucketPolicy`, `GetBucketAcl`, `ListSecrets`, `DescribeParameters`,
  `ListKeys`, `DescribeInstances`, `DescribeSnapshots`, `DescribeSecurityGroups`, `DescribeTrails`
- bursts of `AccessDenied` across many services from one identity

**Privilege escalation and persistence** (`iam.amazonaws.com`, `sts.amazonaws.com`)
- `CreateUser`, `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`
- `AttachUserPolicy`, `AttachRolePolicy`, `PutUserPolicy`, `PutRolePolicy`, `AddUserToGroup`
- `CreatePolicyVersion` with `setAsDefault`, `SetDefaultPolicyVersion`
- `UpdateAssumeRolePolicy` (widening a role's trust to an external account is the classic backdoor)
- `CreateRole` with a trust policy naming an unknown account
- `DeactivateMFADevice`, `DeleteVirtualMFADevice`
- `CreateSAMLProvider`, `UpdateSAMLProvider`, `CreateOpenIDConnectProvider`
- `AssumeRole` chains: an `AssumedRole` identity calling `AssumeRole` into a more privileged role
- Lambda: `CreateFunction20150331`, `UpdateFunctionCode20150331v2`, `AddPermission20150331v2`;
  EventBridge `PutRule` / `PutTargets` (scheduled persistence)
- EC2: `ModifyInstanceAttribute` (user data), `CreateKeyPair`, `ImportKeyPair`

**Defense evasion** (`cloudtrail.amazonaws.com`, `guardduty.amazonaws.com`, `config.amazonaws.com`, `logs.amazonaws.com`, `ec2.amazonaws.com`)
- `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` (dropping data events)
- `DeleteDetector`, `UpdateDetector` (GuardDuty), `DeleteMembers`, `DisassociateFromMasterAccount`
- `StopConfigurationRecorder`, `DeleteConfigurationRecorder`, `DeleteDeliveryChannel`
- `DeleteLogGroup`, `DeleteLogStream`, `PutRetentionPolicy` (shortening retention)
- `DeleteFlowLogs`
- `DisableAlarmActions`, `DeleteAlarms`; EventBridge `DisableRule`, `DeleteRule`
- `LeaveOrganization` (escapes SCPs)

**Credential access and collection** (`secretsmanager.amazonaws.com`, `ssm.amazonaws.com`, `kms.amazonaws.com`, `s3.amazonaws.com`, `ec2.amazonaws.com`, `rds.amazonaws.com`)
- `GetSecretValue`, `BatchGetSecretValue`, `GetParameter(s)`, `GetParametersByPath` (with `withDecryption`)
- `Decrypt` bursts from one identity (KMS logs the key ARN, not the plaintext)
- `GetObject` in volume or across many buckets (needs data events); `GetObject` from a
  new IP by an instance role is the SSRF/stolen-instance-credential signature
- `CreateSnapshot`, `CopySnapshot`, `ModifySnapshotAttribute` (share to another account),
  `ModifyImageAttribute`, `ModifyDBSnapshotAttribute`, `CreateDBSnapshot` then share
- `GetPasswordData` (Windows instance admin password)
- `SendCommand`, `StartSession` (SSM) against instances the identity does not normally touch

**Exfiltration and impact** (`s3.amazonaws.com`, `ec2.amazonaws.com`, `kms.amazonaws.com`)
- `PutBucketPolicy` / `PutBucketAcl` granting an external principal or `*`
- `DeletePublicAccessBlock`, `PutBucketPublicAccessBlock` with blocks set to false
- `PutBucketReplication` to an external bucket
- `PutBucketVersioning` (suspend), `PutBucketLifecycle(Configuration)` (short expiry),
  `DeleteObject(s)` in volume: S3 ransomware pattern
- `ScheduleKeyDeletion`, `DisableKey`, `PutKeyPolicy` (KMS ransom)
- `RunInstances` in unusual regions or large instance types (crypto-mining); `AuthorizeSecurityGroupIngress` opening `0.0.0.0/0`
- `DeleteDBInstance`, `DeleteSnapshot`, `TerminateInstances` in volume

## Athena SQL over CloudTrail

Assumes the partitioned table from the AWS documentation (`cloudtrail_logs` with
`useridentity` as a struct and `requestparameters` / `responseelements` as JSON strings).
Always bound by partition columns or `eventtime` first; CloudTrail tables are large.
Field names are lowercase in Athena.

```sql
-- Everything one identity did, in order
SELECT eventtime, eventsource, eventname, sourceipaddress, useragent, errorcode,
       useridentity.arn, requestparameters
FROM cloudtrail_logs
WHERE eventtime BETWEEN '2026-09-07T00:00:00Z' AND '2026-09-14T23:59:59Z'
  AND (useridentity.arn LIKE '%user/alice.dev%' OR useridentity.accesskeyid = 'ASIAEXAMPLESESSION01')
ORDER BY eventtime;

-- Console logins without MFA
SELECT eventtime, useridentity.arn, sourceipaddress, useragent,
       json_extract_scalar(additionaleventdata, '$.MFAUsed') AS mfa,
       json_extract_scalar(responseelements, '$.ConsoleLogin') AS outcome
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND eventtime >= '2026-09-01'
  AND json_extract_scalar(additionaleventdata, '$.MFAUsed') = 'No';

-- Access keys created, by whom, for whom
SELECT eventtime, useridentity.arn AS creator, sourceipaddress,
       json_extract_scalar(requestparameters, '$.userName') AS target_user,
       json_extract_scalar(responseelements, '$.accessKey.accessKeyId') AS new_key
FROM cloudtrail_logs
WHERE eventname = 'CreateAccessKey' AND eventtime >= '2026-09-01';

-- Role assumption chain: who assumed which role, from which IP
SELECT eventtime, useridentity.type, useridentity.arn AS caller,
       json_extract_scalar(requestparameters, '$.roleArn') AS target_role,
       json_extract_scalar(requestparameters, '$.roleSessionName') AS session_name,
       sourceipaddress, errorcode
FROM cloudtrail_logs
WHERE eventname IN ('AssumeRole', 'AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity')
  AND eventtime >= '2026-09-07'
ORDER BY eventtime;

-- Logging tampering
SELECT eventtime, useridentity.arn, eventname, sourceipaddress, requestparameters, errorcode
FROM cloudtrail_logs
WHERE eventname IN ('StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors',
                    'DeleteDetector', 'StopConfigurationRecorder', 'DeleteFlowLogs', 'DeleteLogGroup')
  AND eventtime >= '2026-09-01';

-- New source IPs for an identity vs. its 30-day baseline
WITH baseline AS (
  SELECT DISTINCT sourceipaddress FROM cloudtrail_logs
  WHERE useridentity.arn = 'arn:aws:iam::123456789012:user/alice.dev'
    AND eventtime BETWEEN '2026-08-07' AND '2026-09-06')
SELECT sourceipaddress, min(eventtime) AS first_seen, count(*) AS events
FROM cloudtrail_logs
WHERE useridentity.arn = 'arn:aws:iam::123456789012:user/alice.dev'
  AND eventtime >= '2026-09-07'
  AND sourceipaddress NOT IN (SELECT sourceipaddress FROM baseline)
GROUP BY sourceipaddress;

-- Recon burst: identities with many distinct read-only calls in a short window
SELECT useridentity.arn, date_trunc('minute', from_iso8601_timestamp(eventtime)) AS minute,
       count(*) AS calls, count(DISTINCT eventname) AS distinct_calls,
       sum(CASE WHEN errorcode IS NOT NULL THEN 1 ELSE 0 END) AS errors
FROM cloudtrail_logs
WHERE eventtime >= '2026-09-13' AND readonly = 'true'
GROUP BY 1, 2 HAVING count(DISTINCT eventname) >= 15
ORDER BY calls DESC;

-- Secret and parameter reads
SELECT eventtime, useridentity.arn, eventname, sourceipaddress,
       coalesce(json_extract_scalar(requestparameters, '$.secretId'),
                json_extract_scalar(requestparameters, '$.name')) AS target
FROM cloudtrail_logs
WHERE eventname IN ('GetSecretValue', 'BatchGetSecretValue', 'GetParameter', 'GetParameters', 'GetParametersByPath')
  AND eventtime >= '2026-09-07'
ORDER BY eventtime;
```

CloudTrail Lake uses the same shape with a different table name (the event data store ID)
and native struct fields (`userIdentity.arn`, `requestParameters` as a map). Event history
in the console is limited to 90 days and management events only, but is the fastest first
look.

## Preservation

- **CloudTrail:** confirm `GetTrailStatus` shows `IsLogging: true` and note
  `LatestDeliveryTime`. Copy the S3 prefix for the window to the forensic account with
  Object Lock or at least a bucket the suspect identities cannot reach. The trail bucket
  itself may be attacker-writable if the policy was changed; check it.
- **Compute:** `CreateSnapshot` of every attached EBS volume (tag with the case ID), then
  `ModifySnapshotAttribute` to share with the forensic account and copy there (encrypted
  snapshots need the KMS key shared too). Do not stop the instance if memory matters;
  isolate it with a dedicated security group that allows nothing, remove it from load
  balancers and auto scaling groups, set termination protection, and detach the instance
  profile (`DisassociateIamInstanceProfile`) to stop further credential use.
- **Serverless:** `GetFunction` returns a pre-signed URL for the deployment package; download
  it and record the SHA-256. Export the function configuration and environment variables
  (they often contain the leaked secret).
- **IAM state:** `GetAccountAuthorizationDetails` output and the credential report at the
  start of the investigation, so you can diff after eradication.
- **Findings:** export GuardDuty findings and Security Hub findings for the window as JSON.
- **Retention traps:** Event history is 90 days; CloudWatch log groups may have short
  retention; VPC flow logs to CloudWatch can be deleted by the same identity. Copy early.

## Containment

| Action | API / console | Blast radius and cautions |
|---|---|---|
| Deactivate a user's access key | `UpdateAccessKey --status Inactive` | reversible; anything legitimately using the key breaks, which is usually acceptable. Delete only after closure |
| Revoke a user's console sessions | `DeleteLoginProfile` or set a new password + force MFA | ends console sessions; API keys unaffected |
| Revoke active role sessions | IAM console "Revoke active sessions" (adds an inline policy denying everything for sessions issued before now via `aws:TokenIssueTime`) | kills every session of that role including production workloads; they recover on next credential refresh. Coordinate with the owner |
| Quarantine a principal | attach an explicit deny-all policy (`Effect: Deny, Action: *, Resource: *`) | preserves the principal for evidence; explicit deny wins over any allow; prefer this to deleting |
| Block an external account | SCP or resource-policy edit removing the principal; `UpdateAssumeRolePolicy` to restore trust | check every role's trust policy, not only the one you found |
| Stop an instance's credential use | `DisassociateIamInstanceProfile`, isolation security group | instance keeps running for forensics; app on it will fail |
| Undo public exposure | `PutPublicAccessBlock` (account) and per-bucket; `DeleteBucketPolicy` or restore from Config history | account-level block can break legitimate public buckets; check first |
| Prevent recurrence org-wide | SCP denying `cloudtrail:StopLogging`, `iam:CreateAccessKey` on root, `organizations:LeaveOrganization`, region restrictions | SCPs do not apply to the management account; test in a sandbox OU first |
| Root credentials | rotate root password, remove root access keys, enable hardware MFA | requires access to the root email and existing MFA; involve account owner |

After containment, re-query for activity by the contained principals. Anything but
`AccessDenied` means the containment missed a credential.
