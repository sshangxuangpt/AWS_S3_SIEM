# AWS S3 Athena (SIEM)

Polls a detections table in AWS Athena for FortiGate detection alerts, turns each into a
Cortex XSOAR incident, and drills back to the raw FortiGate log lines that fired a detection
on demand.

Authentication is a two-step flow (the same one the **AWS - Athena - Beta** content pack uses):
a static IAM access key whose only permission is to assume a read-only role, then an STS
`AssumeRole` into that role to talk to Athena with the temporary credentials.

## Prerequisites

- An IAM access key / secret key for a user that can **only** assume the reader role.
- The read-only role ARN it assumes (e.g. `detections-reader`), with access to the detections
  table, the raw log tables, the Athena workgroup, and the S3 buckets behind them.
- The Athena workgroup, database, and (optionally) the S3 query-results location.
- Network access from the XSOAR engine/server to the AWS Athena and STS endpoints.

## Configure AWS S3 Athena (SIEM) on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Instances**.
2. Search for **AWS S3 Athena (SIEM)**.
3. Click **Add instance** to create and configure a new integration instance.

   | Parameter (`name`) | Display name | Type | Required | Example / notes |
   |---|---|---|---|---|
   | `defaultRegion` | AWS Default Region | Short text | True | `ap-southeast-1` |
   | `roleArn` | Role Arn | Short text | True | `arn:aws:iam::942510828162:role/detections-reader` |
   | `roleSessionName` | Role Session Name | Short text | True | `xsoar-detections` |
   | `sessionDuration` | Role Session Duration (seconds) | Short text | False | Optional STS session length, e.g. `3600` |
   | `credentials` | Access Key / Secret Key | Authentication (2 fields) | True | Access Key id in the first field, Secret Key in the password field |
   | `workgroup` | Athena Workgroup | Short text | True | `wayne` |
   | `database` | Athena Database | Short text | True | `baselines` |
   | `catalog` | Athena Data Catalog | Short text | False | `AwsDataCatalog` |
   | `outputLocation` | Query Result S3 Output Location | Short text | False | `s3://mss-log-fabric-8162-athena-results/wayne/` (omit if the workgroup enforces one) |
   | `tenant_id` | Tenant ID | Short text | False* | `suju` — *required for fetching / commands* |
   | `detection_status` | Detection status filter | Short text | False | `ES` |
   | `isFetch` | Fetch incidents | Boolean | False | Enable to pull detections as incidents |
   | `incidentType` | Incident type | Incident-type picker | False | The XSOAR incident type to create |
   | `first_fetch` | First fetch timestamp | Short text | False | `3 days`, `12 hours`, or `YYYY-MM-DD HH:MM:SS` |
   | `max_fetch` | Maximum number of incidents per fetch | Short text | False | `50` |
   | `insecure` | Trust any certificate (not secure) | Boolean | False | Skip TLS verification |
   | `proxy` | Use system proxy settings | Boolean | False | Route through the system proxy |

   \* `tenant_id` is optional at the platform level so the **Test** button works without it,
   but fetching and both commands raise an error when it is empty. Treat it as required.

4. Click **Test** to validate the connection (see below).
5. If you want incidents, tick **Fetch incidents**, set **Tenant ID**, **First fetch timestamp**,
   **Maximum number of incidents per fetch**, an **Incident type**, and the collection interval,
   then click **Done**.

### Test

The **Test** button runs `test-module`: it assumes the configured role via STS and makes a
lightweight `list_work_groups` call. A green result confirms the credentials, region, and role
permissions. When **Fetch incidents** is enabled it also checks that the first-fetch timestamp
parses and that a Tenant ID is set.

## Fetch incidents

When enabled, each collection interval polls the detections table for
`tenant_id = <Tenant ID>` and `status = <Detection status filter>` where
`detected_at >= watermark`. Each returned row becomes an incident:

| Incident field | Source |
|---|---|
| name | `<rule_id> - <identity>` |
| occurred | `event_time` (the activity time) |
| severity | source severity `1`–`5` mapped to XSOAR (`1`→Info, `2`→Low, `3`→Medium, `4`→High, `5`→Critical) |
| dbotMirrorId | `dedup_key` |
| rawJSON | the full detection row, with `event_details` parsed and the `_drillback` recipe extracted under `drillback` |

**No missed and no duplicate alerts.** The watermark is the largest `detected_at` seen. Because
several detections can share the exact same `detected_at`, the last run also stores the set of
`dedup_key`s already emitted at that timestamp. The next poll queries `detected_at >= watermark`
(inclusive) and skips any `dedup_key` already in that set — so a detection landing exactly on the
boundary is emitted once and only once, and a late-arriving detection at that timestamp is still
picked up on a later run.

> To map the parsed `event_details` fields onto incident fields, attach a classifier and mapper
> to the instance. This is optional — the integration works without one.

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook. After
you successfully execute a command, a DBot message appears in the War Room with the command
details.

### aws-s3-athena-get-detections

***
Runs the detections poll on demand (useful for manual triage and for testing before enabling
fetch). This query is cheap — safe to run interactively.

#### Base Command

`aws-s3-athena-get-detections`

#### Input

| **Argument Name** | **Description** | **Required** |
|---|---|---|
| tenant_id | The `tenant_id` to poll. Defaults to the instance Tenant ID. | Optional |
| status | The `detections.status` value to fetch. Defaults to the instance setting (`ES`). | Optional |
| since | How far back to look — `<number> <unit>` (e.g. `6 hours`) or `YYYY-MM-DD HH:MM:SS`. Default `1 day`. | Optional |
| limit | Maximum number of detections to return. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
|---|---|---|
| AWSS3Athena.Detection.dedup_key | String | The detection dedup key (unique id). |
| AWSS3Athena.Detection.rule_id | String | The source rule id. |
| AWSS3Athena.Detection.severity | String | The source rule severity (1-5). |
| AWSS3Athena.Detection.identity | String | The detection identity (e.g. source IP). |
| AWSS3Athena.Detection.event_time | Date | The activity time of the detection. |
| AWSS3Athena.Detection.detected_at | Date | When the detection was raised (the fetch watermark). |
| AWSS3Athena.Detection.evidence_count | Number | The evidence count for the detection. |

#### Command Example

```
!aws-s3-athena-get-detections since="2 days" limit=20
```

### aws-s3-athena-get-raw-event

***
Drills back to the raw FortiGate log lines that fired a detection.

> **Warning:** this scans GBs of raw logs (~4 GB/query). Run it on incident-open only, never
> per poll.

Specify the target one of three ways (precedence: `drillback` → `dedup_key` → explicit
`table`/`from_time`/`to_time`):

1. **`dedup_key`** — the integration looks the detection up and reads its `_drillback` recipe
   (optionally scoped by `tenant_id`).
2. **`drillback`** — a raw recipe as JSON: `{"table":...,"from":...,"to":...,"like":[...]}`.
3. **`table` + `from_time` + `to_time`** (+ optional comma-separated `like`) — build the recipe
   explicitly.

#### Base Command

`aws-s3-athena-get-raw-event`

#### Input

| **Argument Name** | **Description** | **Required** |
|---|---|---|
| dedup_key | The detection `dedup_key`. The integration looks up its `_drillback` recipe and runs it. | Optional |
| tenant_id | Optional `tenant_id` to scope the dedup_key lookup. Defaults to the instance Tenant ID. | Optional |
| drillback | A raw drillback recipe as JSON: `{"table":...,"from":...,"to":...,"like":[...]}`. Takes precedence over `dedup_key`. | Optional |
| table | Raw log table to scan (used with `from_time`/`to_time`/`like` when no `dedup_key`/`drillback` is given). | Optional |
| from_time | Window start, `YYYY-MM-DD HH:MM:SS`. | Optional |
| to_time | Window end, `YYYY-MM-DD HH:MM:SS`. | Optional |
| like | Comma-separated list of substrings each raw message must contain (e.g. `srcip=10.0.0.1 ,dstport=161 `). | Optional |
| limit | Maximum number of raw lines to return. Default `1000`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
|---|---|---|
| AWSS3Athena.RawEvent.DedupKey | String | The detection dedup_key the raw events were drilled back from. |
| AWSS3Athena.RawEvent.EventCount | Number | Number of raw log lines returned. |
| AWSS3Athena.RawEvent.Drillback | Unknown | The drillback recipe that was executed. |
| AWSS3Athena.RawEvent.Events.start_time | Date | The event start time (from `_time`). |
| AWSS3Athena.RawEvent.Events.rawstring | String | The raw FortiGate log line. |

#### Command Examples

By `dedup_key` (easiest — the recipe is looked up for you):

```
!aws-s3-athena-get-raw-event dedup_key=4D56284448E77B946C81A947A9E4B2B154F61A33DF733134CF8C52D4378BA6CA
```

By explicit window:

```
!aws-s3-athena-get-raw-event table=sources.suju__fortigate_hourly from_time="2026-07-06 01:00:00" to_time="2026-07-06 01:05:00" like="srcip=10.208.48.20 ,dstport=161 " limit=500
```

Inside an incident playbook, using the fetched detection's mirror id:

```
!aws-s3-athena-get-raw-event dedup_key=${incident.dbotMirrorId}
```

## Typical workflow

1. Configure the instance and click **Test**.
2. Run `!aws-s3-athena-get-detections since="2 days"` to confirm detections flow.
3. Enable **Fetch incidents** so detections auto-create incidents on the interval.
4. On incident-open, run `!aws-s3-athena-get-raw-event dedup_key=${incident.dbotMirrorId}` to
   pull the raw FortiGate lines behind the detection.

## Notes

- **Poll is cheap; drill-back scans ~4 GB/query** — keep drill-back to incident-open.
- `detected_at` is the fetch watermark and is persisted, not shown as the event time. The
  activity time is `event_time`.
- `event_details` and its `_drillback` field are JSON **strings**; array-valued labels need a
  second parse. The integration unwraps `_drillback` for you.
- `severity` is a number `1`–`5` (OCSF `severity_id`), not a text label.
