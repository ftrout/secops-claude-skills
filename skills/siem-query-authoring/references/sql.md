# SQL: Athena and BigQuery over cloud logs

When cloud logs sit in object storage (CloudTrail, VPC flow logs, Route 53 resolver logs,
ALB logs in S3; audit logs exported to BigQuery), the SIEM is a SQL engine. Athena
(Trino/Presto dialect) and BigQuery (GoogleSQL) share most syntax; the differences that
bite are timestamp handling, nested field access, and how partitions are pruned. Based on
AWS Athena and Google BigQuery documentation, 2025-2026.

## Tables and the columns that matter

### CloudTrail (Athena, table created per the AWS "Querying CloudTrail logs" guide)

| Column | Notes |
|---|---|
| `eventtime` | string, ISO 8601 UTC (`2026-09-17T10:15:32Z`); convert with `from_iso8601_timestamp()` |
| `eventname`, `eventsource` | `ConsoleLogin`, `CreateAccessKey`, `AssumeRole`; `iam.amazonaws.com` etc. |
| `useridentity` | struct: `useridentity.type` (IAMUser, AssumedRole, Root, AWSService), `useridentity.arn`, `useridentity.username`, `useridentity.accountid`, `useridentity.sessioncontext.sessionissuer.arn` |
| `sourceipaddress`, `useragent` | Service principals appear as `*.amazonaws.com` in `sourceipaddress` |
| `awsregion`, `recipientaccountid` | Scope |
| `errorcode`, `errormessage` | `AccessDenied`, `UnauthorizedOperation`; failures are the hunt signal |
| `requestparameters`, `responseelements` | JSON strings; parse with `json_extract_scalar()` |
| `additionaleventdata` | JSON string; `MFAUsed` for ConsoleLogin lives here |
| `readonly` | boolean; `false` = mutating call |
| Partition columns | Depends on table DDL: `region`, `year`, `month`, `day` or `timestamp` projection; **always filter on them** |

### VPC flow logs (Athena)

`version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets,
bytes, start, end, action, log_status` plus v3-v5 fields when enabled (`vpc_id`,
`subnet_id`, `instance_id`, `tcp_flags`, `flow_direction`, `pkt_srcaddr`, `pkt_dstaddr`).
`start`/`end` are epoch seconds (`from_unixtime(start)`); `action` is `ACCEPT`/`REJECT`.

### Route 53 resolver query logs (Athena)

`version, account_id, region, vpc_id, query_timestamp, query_name, query_type, query_class,
rcode, answers (array of struct), srcaddr, srcport, transport, srcids (struct with
instance)`. `query_timestamp` is ISO 8601 string.

### ALB access logs (Athena)

`time, elb, client_ip, client_port, target_ip, request_verb, request_url, user_agent,
elb_status_code, target_status_code, received_bytes, sent_bytes, ssl_cipher, ...`
(columns follow the AWS-provided regex DDL).

### BigQuery: Cloud Audit Logs export

Table `<project>.<dataset>.cloudaudit_googleapis_com_activity` (and `_data_access`,
`_system_event`), partitioned by `timestamp`. Columns: `timestamp`, `protopayload_auditlog`
(struct: `authenticationInfo.principalEmail`, `methodName`, `serviceName`,
`resourceName`, `requestMetadata.callerIp`, `requestMetadata.callerSuppliedUserAgent`,
`status.code`, `authorizationInfo` array), `resource.type`, `resource.labels`, `severity`,
`logName`.

## Time bounding and partition pruning

```sql
-- Athena, CloudTrail with year/month/day partitions
SELECT eventtime, eventname, useridentity.arn, sourceipaddress, errorcode
FROM cloudtrail_logs
WHERE year = '2026' AND month = '09' AND day BETWEEN '10' AND '17'      -- prunes partitions (cheap)
  AND from_iso8601_timestamp(eventtime) >= timestamp '2026-09-10 00:00:00 UTC'  -- exact window
  AND eventname = 'ConsoleLogin'
ORDER BY eventtime DESC
LIMIT 100;

-- Athena, relative window
WHERE from_iso8601_timestamp(eventtime) >= current_timestamp - interval '30' day

-- BigQuery, partitioned by timestamp
WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
  AND protopayload_auditlog.methodName = 'SetIamPolicy'
```

Athena charges per byte scanned; a query without partition predicates over a year of
CloudTrail scans everything. BigQuery is the same story with its partition column. The
partition filter is not optional.

## Case sensitivity

- Athena string comparison is case-sensitive; `lower(useragent) LIKE '%python%'`.
- BigQuery likewise; `LOWER()` or `REGEXP_CONTAINS(x, r'(?i)pattern')`.
- CloudTrail `eventname` is CamelCase and consistent; `useridentity.username` may not be.

## Count first, then rows

```sql
SELECT sourceipaddress, COUNT(*) AS hits, MIN(eventtime) AS first_seen, MAX(eventtime) AS last_seen
FROM cloudtrail_logs
WHERE year = '2026' AND month = '09'
  AND sourceipaddress IN ('203.0.113.56', '198.51.100.23')
GROUP BY sourceipaddress
ORDER BY hits DESC;
```

## Nested data

```sql
-- Athena: JSON strings
json_extract_scalar(requestparameters, '$.userName')
json_extract_scalar(additionaleventdata, '$.MFAUsed') = 'No'
-- Athena: arrays of structs
CROSS JOIN UNNEST(answers) AS t(answer)   -- Route 53 answers
-- BigQuery: structs and arrays
protopayload_auditlog.authenticationInfo.principalEmail
, UNNEST(protopayload_auditlog.authorizationInfo) AS auth  WHERE auth.granted = false
JSON_VALUE(protopayload_auditlog.metadataJson, '$.event_type')
```

## Lookups and joins

```sql
-- IOC table in S3 (Athena) or a small BigQuery table
SELECT c.eventtime, c.eventname, c.useridentity.arn, c.sourceipaddress, i.role
FROM cloudtrail_logs c
JOIN ioc_list i ON c.sourceipaddress = i.indicator
WHERE c.year = '2026' AND c.month = '09' AND i.type = 'ipv4';
```

- Put the small table on the right of the join (Athena broadcasts it).
- `IN (...)` lists of a few hundred literals are fine; thousands belong in a table.
- Athena CTAS/`UNLOAD` to save a hunt result set for follow-up queries instead of
  re-scanning.

## Useful idioms

```sql
-- stack rare user agents per principal
SELECT useridentity.arn, useragent, COUNT(*) c FROM cloudtrail_logs WHERE ... GROUP BY 1,2 ORDER BY c ASC LIMIT 50;
-- first-seen for each (principal, region) pair
SELECT useridentity.arn, awsregion, MIN(eventtime) FROM cloudtrail_logs WHERE ... GROUP BY 1,2;
-- failures by identity
SELECT useridentity.arn, errorcode, COUNT(*) FROM cloudtrail_logs WHERE errorcode IS NOT NULL AND ... GROUP BY 1,2 ORDER BY 3 DESC;
-- flow: bytes out to an external IP per source
SELECT srcaddr, dstaddr, SUM(bytes) b FROM vpc_flow_logs WHERE ... AND action = 'ACCEPT' GROUP BY 1,2 ORDER BY b DESC;
-- Athena hourly buckets
date_trunc('hour', from_iso8601_timestamp(eventtime))
-- BigQuery hourly buckets
TIMESTAMP_TRUNC(timestamp, HOUR)
```

## Performance pitfalls

- Missing partition predicates (see above). Check the DDL for the partition scheme; some
  tables use partition projection with a `timestamp` column instead of year/month/day.
- `SELECT *` on CloudTrail pulls the large JSON columns; project what you need.
- Regex (`regexp_like`) over `requestparameters` for a month of logs is slow; filter on
  `eventname`/`eventsource` first.
- Athena result limits: 100 MB per query result by default in the console; use `UNLOAD`
  or the API for bigger exports.
- BigQuery: `LIMIT` does not reduce bytes scanned; the partition filter does. Use
  `--dry_run` or the UI estimate before a wide query.
- CloudTrail delivery lag is up to 15 minutes; data access events and Insights are
  separate trails. Confirm which trails feed the table before concluding "no events".
