# AWS_S3_SIEM

# Wayne → XSOAR detections — test package

Validate the Wayne detections **poll** and raw-log **drill-back** before wiring the Cortex
XSOAR "AWS - Athena - Beta" integration. It's a Jupyter notebook — each query is a cell.

## Contents
- `xsoar_detections.ipynb` — the notebook: assume-role → poll query → inspect one
  detection's variables → drill-back query.
- `xsoar-detections.env` — the static AWS credential + role ARN the notebook reads.

## The credential (what goes into the XSOAR integration)
| XSOAR field | Value |
|---|---|
| Access Key | `AWS_ACCESS_KEY_ID` in the env file |
| Secret Key | `AWS_SECRET_ACCESS_KEY` in the env file |
| Role Arn | `arn:aws:iam::942510828162:role/detections-reader` |
| Role Session Name | `xsoar-detections` |
| Default Region | `ap-southeast-1` |
| Athena workgroup | `wayne` |

The access key belongs to an IAM user that can do **nothing** except assume
`detections-reader` — read-only on the detections tables, the raw source logs, the `wayne`
Athena workgroup, and the S3 behind them. Same two-step (key → assume-role) auth the XSOAR
content pack uses.

## Run it
```bash
pip install boto3 jupyter
# keep xsoar-detections.env in the same folder as the notebook
jupyter notebook xsoar_detections.ipynb
```
Run the cells top to bottom:
1. **Auth** — reads the credential from `xsoar-detections.env` and assumes the reader role.
2. **Poll** — set `WATERMARK` to your starting timestamp (XSOAR's "First fetch timestamp"),
   run to get detections newer than it. The cell prints the next `WATERMARK` to use.
3. **Variables** — `json.loads(event_details)` for one detection; these are the incident fields.
4. **Drill-back** — reads the `_drillback` recipe on that detection and returns the exact raw
   FortiGate lines that fired it.

## Notes
- **Poll is cheap**; **drill-back scans GBs** of raw logs (~4 GB/query) — run it on
  incident-open only, never per poll.
- `event_details` and its `_drillback` field are JSON **strings**; array-valued labels need
  a second `json.loads`. The notebook shows the pattern.
- `detected_at` is the watermark — persist it, don't show it as the event time. The activity
  time is `event_time` / `occurred`.
- **`severity` is a number `1`–`5`** (the source rule's own severity, OCSF `severity_id`):
  `1`=Informational, `2`=Low, `3`=Medium, `4`=High, `5`=Critical. Map it to XSOAR's incident
  severity (e.g. 1→Info/Low, 2→Low, 3→Medium, 4→High, 5→Critical). It is **not** a text label.
- `event_details` keys are the source SIEM's own field names (e.g. `source.ip`, `Vendor.action`,
  `event.action`, `Vendor.subtype`); they vary by rule and are the fields to populate the incident.
