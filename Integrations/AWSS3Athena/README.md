# AWS S3 Athena (SIEM) — Cortex XSOAR integration

Turns the `xsoar_detections.ipynb` proof-of-concept into a Cortex XSOAR integration.
It polls the Wayne **detections** table in AWS Athena for FortiGate detection "alerts",
creates XSOAR incidents from them, and drills back to the raw FortiGate log lines that
fired a detection on demand.

It reuses the two-step authentication of the existing **AWS - Athena - Beta** content pack:
a static IAM access key that can do nothing except assume a read-only role, then STS
`AssumeRole` into that role and talk to Athena with the temporary credentials.

## What maps to what

| Notebook step | Integration equivalent |
|---|---|
| Auth cell (key → assume `detections-reader`) | `aws_session()` helper + instance parameters |
| `run_sql()` | `run_sql()` (start → poll → page results) |
| Poll cell (detections newer than `WATERMARK`) | `fetch-incidents` and `aws-s3-athena-get-detections` |
| `event_details` / `json.loads` | parsed into each incident's `rawJSON` |
| Drill-back cell (`_drillback` recipe → raw logs) | `aws-s3-athena-get-raw-event` |

## Configuration

| Parameter | Notes |
|---|---|
| AWS Default Region | e.g. `ap-southeast-1` |
| Role Arn | the reader role to assume, e.g. `arn:aws:iam::942510828162:role/detections-reader` |
| Role Session Name | e.g. `xsoar-detections` |
| Role Session Duration | optional STS duration (seconds) |
| Access Key / Secret Key | the static IAM user credential (only permitted to assume the reader role) |
| Athena Workgroup | e.g. `wayne` |
| Athena Database | e.g. `baselines` |
| Athena Data Catalog | defaults to `AwsDataCatalog` |
| Query Result S3 Output Location | e.g. `s3://mss-log-fabric-8162-athena-results/wayne/` (optional if the workgroup enforces one) |
| Tenant ID | the `tenant_id` filter for the poll (required for fetching) |
| Detection status filter | the `detections.status` value to fetch (default `ES`) |
| First fetch timestamp | e.g. `3 days` or `YYYY-MM-DD HH:MM:SS` |
| Maximum incidents per fetch | default `50` |

## Commands

### `test-module` (Test button)
Assumes the role and runs a lightweight Athena call (`list_work_groups`) to confirm
connectivity and credentials. When *Fetch incidents* is on it also validates the first-fetch
timestamp and that a Tenant ID is set.

### Fetch incidents
Polls `detections` for `tenant_id = <Tenant ID>` and `status = <filter>` where
`detected_at >= watermark`. Each row becomes an incident:

- **name**: `<rule_id> - <identity>`
- **occurred**: the activity time (`event_time`)
- **severity**: the source rule severity `1`–`5` mapped to XSOAR
  (`1`→Info, `2`→Low, `3`→Medium, `4`→High, `5`→Critical)
- **dbotMirrorId**: the `dedup_key`
- **rawJSON**: the full row, with `event_details` parsed and the `_drillback` recipe
  extracted under `drillback`

**No missed, no duplicate alerts.** The watermark is the largest `detected_at` seen. Because
several detections can share the exact same `detected_at`, the last run also stores the set of
`dedup_key`s already emitted at that timestamp. The next poll uses `detected_at >= watermark`
(inclusive) and skips any `dedup_key` already in that set — so a detection landing exactly on
the boundary is emitted once and only once, and a late-arriving detection at the boundary
timestamp is still picked up.

### `aws-s3-athena-get-raw-event`
Drills back to the raw FortiGate log lines that fired a detection. **Scans GBs of raw logs —
run on incident-open only, never per poll.** Specify the target one of three ways:

1. `dedup_key` — the integration looks the detection up and reads its `_drillback` recipe
   (optionally scoped by `tenant_id`).
2. `drillback` — a raw recipe as JSON: `{"table":...,"from":...,"to":...,"like":[...]}`.
3. `table` + `from_time` + `to_time` (+ optional comma-separated `like`) — build the recipe
   explicitly.

Output goes to `AWSS3Athena.RawEvent` (`DedupKey`, `EventCount`, `Drillback`, and
`Events[].{start_time, rawstring}`).

### `aws-s3-athena-get-detections`
Runs the poll on demand for manual triage/testing (cheap). Arguments: `tenant_id`, `status`,
`since` (e.g. `6 hours` or a timestamp), `limit`. Output goes to `AWSS3Athena.Detection`.

## Notes carried over from the notebook

- **Poll is cheap; drill-back scans ~4 GB/query** — keep drill-back to incident-open.
- `detected_at` is the watermark; it is persisted, not shown as the event time. The activity
  time is `event_time`.
- `event_details` and its `_drillback` field are JSON **strings**; array-valued labels need a
  second `json.loads`. The integration handles the `_drillback` unwrap for you.
- `severity` is a number `1`–`5` (OCSF `severity_id`), not a text label.
