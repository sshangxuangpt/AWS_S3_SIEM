"""AWS S3 Athena (SIEM) — Cortex XSOAR integration.

Polls the Wayne detections table in AWS Athena for FortiGate "detection" alerts
and, on demand, drills back to the raw FortiGate log lines that fired a detection.

Auth is the same two-step flow the notebook / "AWS - Athena - Beta" pack use:
a static IAM access key that can do nothing except assume a read-only role, then
STS assume-role into that role and talk to Athena with the temporary credentials.

Transport is plain HTTPS signed with AWS Signature V4 (via `requests`), so the
integration runs on the default `demisto/python3` image — no boto3 required.
"""

import hashlib
import hmac
import json
import time
import xml.etree.ElementTree as ET
from datetime import datetime, date, timezone
from urllib.parse import urlencode

import requests
import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403
from CommonServerUserPython import *  # noqa: F401,F403

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

# Terminal states of an Athena query execution.
TERMINAL_STATES = ("SUCCEEDED", "FAILED", "CANCELLED")
# How long to poll a single Athena query before giving up (seconds).
DEFAULT_QUERY_TIMEOUT = 120
QUERY_POLL_INTERVAL = 1.5
DEFAULT_MAX_FETCH = 50
FETCH_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
# Detected_at is what Athena hands back, e.g. "2026-07-06 01:31:16.923000".
DETECTED_AT_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
# HTTP (connect, read) timeouts in seconds.
HTTP_TIMEOUT = (10, 60)

STS_API_VERSION = "2011-06-15"
ATHENA_JSON_CONTENT_TYPE = "application/x-amz-json-1.1"
STS_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded; charset=utf-8"

# The source rule's own severity (OCSF severity_id, 1-5) mapped to an XSOAR
# incident severity. See the pack README for the rationale.
#   1 Informational -> 0.5 Info      2 Low       -> 1 Low
#   3 Medium        -> 2 Medium      4 High      -> 3 High
#   5 Critical      -> 4 Critical
SEVERITY_MAP = {
    "1": 0.5,
    "2": 1,
    "3": 2,
    "4": 3,
    "5": 4,
}

""" HELPER FUNCTIONS """


class DatetimeEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime("%Y-%m-%dT%H:%M:%S")
        elif isinstance(obj, date):
            return obj.strftime("%Y-%m-%d")
        return json.JSONEncoder.default(self, obj)


def _params() -> dict:
    return demisto.params()


""" AWS TRANSPORT (SigV4 over requests, no boto3) """


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret_key: str, datestamp: str, region: str, service: str) -> bytes:
    k_date = _sign(("AWS4" + secret_key).encode("utf-8"), datestamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    return _sign(k_service, "aws4_request")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def sigv4_request(service, region, body, content_type, creds, verify, proxies,
                  amz_target=None, now=None):
    """Sign an AWS request with Signature V4 and POST it. Returns the Response.

    `creds` is {access_key, secret_key, token}; `token` may be None (static key)
    or the STS session token (temporary credentials).
    """
    host = f"{service}.{region}.amazonaws.com"
    endpoint = f"https://{host}/"
    now = now or _utcnow()
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")

    payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

    # Headers that are part of the signature (must be lowercase and sorted).
    signed = {
        "content-type": content_type,
        "host": host,
        "x-amz-date": amzdate,
    }
    if creds.get("token"):
        signed["x-amz-security-token"] = creds["token"]
    if amz_target:
        signed["x-amz-target"] = amz_target

    signed_headers = ";".join(sorted(signed))
    canonical_headers = "".join(f"{k}:{signed[k]}\n" for k in sorted(signed))
    canonical_request = "\n".join([
        "POST", "/", "", canonical_headers, signed_headers, payload_hash,
    ])

    algorithm = "AWS4-HMAC-SHA256"
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        algorithm,
        amzdate,
        scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
    ])

    signature = hmac.new(
        _signing_key(creds["secret_key"], datestamp, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    authorization = (
        f"{algorithm} Credential={creds['access_key']}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    # Actual HTTP headers: everything signed except host (requests sets Host from
    # the URL, matching what we signed), plus the Authorization header.
    http_headers = {k: v for k, v in signed.items() if k != "host"}
    http_headers["Authorization"] = authorization

    return requests.post(
        endpoint,
        data=body.encode("utf-8"),
        headers=http_headers,
        verify=verify,
        proxies=proxies or {},
        timeout=HTTP_TIMEOUT,
    )


def _xml_find_text(root, localname):
    """Namespace-agnostic first-match text lookup in an XML tree."""
    for el in root.iter():
        if el.tag.split("}")[-1] == localname:
            return el.text
    return None


def assume_role(static_creds, region, role_arn, role_session_name, role_session_duration,
                verify, proxies) -> dict:
    """Call STS AssumeRole with the static key; return temporary credentials."""
    form = {
        "Action": "AssumeRole",
        "Version": STS_API_VERSION,
        "RoleArn": role_arn,
        "RoleSessionName": role_session_name,
    }
    if role_session_duration:
        form["DurationSeconds"] = str(int(role_session_duration))
    body = urlencode(form)

    resp = sigv4_request(
        service="sts",
        region=region,
        body=body,
        content_type=STS_FORM_CONTENT_TYPE,
        creds=static_creds,
        verify=verify,
        proxies=proxies,
    )
    if resp.status_code != 200:
        message = _xml_find_text(_safe_xml(resp.text), "Message") or resp.text
        raise DemistoException(f"STS AssumeRole failed ({resp.status_code}): {message}")

    root = ET.fromstring(resp.text)
    access_key = _xml_find_text(root, "AccessKeyId")
    secret_key = _xml_find_text(root, "SecretAccessKey")
    token = _xml_find_text(root, "SessionToken")
    if not (access_key and secret_key and token):
        raise DemistoException("STS AssumeRole returned no credentials.")
    return {"access_key": access_key, "secret_key": secret_key, "token": token}


def _safe_xml(text):
    try:
        return ET.fromstring(text)
    except ET.ParseError:
        return ET.Element("empty")


def get_client() -> dict:
    """Resolve credentials (assuming the role if configured) and return a client.

    The returned dict carries the effective credentials plus the region and HTTP
    settings needed to sign every subsequent Athena call.
    """
    params = _params()

    access_key = params.get("credentials", {}).get("identifier") or params.get("access_key")
    secret_key = params.get("credentials", {}).get("password") or params.get("secret_key")
    role_arn = params.get("roleArn")
    role_session_name = params.get("roleSessionName") or "xsoar-detections"
    role_session_duration = params.get("sessionDuration")
    region = params.get("defaultRegion")
    verify = not params.get("insecure", False)
    proxies = handle_proxy(proxy_param_name="proxy", checkbox_default_value=False)

    if not access_key or not secret_key:
        raise DemistoException("AWS Access Key and Secret Key are required.")
    if not region:
        raise DemistoException("AWS Default Region is required.")

    static_creds = {"access_key": access_key, "secret_key": secret_key, "token": None}
    creds = static_creds
    if role_arn:
        creds = assume_role(
            static_creds, region, role_arn, role_session_name, role_session_duration,
            verify, proxies,
        )

    return {"region": region, "creds": creds, "verify": verify, "proxies": proxies}


def athena_call(client: dict, action: str, payload: dict) -> dict:
    """Invoke an Athena JSON API action (e.g. 'StartQueryExecution')."""
    resp = sigv4_request(
        service="athena",
        region=client["region"],
        body=json.dumps(payload),
        content_type=ATHENA_JSON_CONTENT_TYPE,
        creds=client["creds"],
        verify=client["verify"],
        proxies=client["proxies"],
        amz_target=f"AmazonAthena.{action}",
    )
    if resp.status_code != 200:
        try:
            err = resp.json()
            message = err.get("Message") or err.get("message") or err.get("__type") or resp.text
        except ValueError:
            message = resp.text
        raise DemistoException(f"Athena {action} failed ({resp.status_code}): {message}")
    return resp.json() if resp.text else {}


def run_sql(client: dict, sql: str, timeout: int = DEFAULT_QUERY_TIMEOUT) -> list:
    """Run an Athena query synchronously and return rows as a list of dicts.

    Mirrors the notebook's run_sql: start execution, poll until terminal, then
    page through all results. The header row becomes the dict keys.
    """
    params = _params()
    kwargs = {
        "QueryString": sql,
        "QueryExecutionContext": {
            "Database": params.get("database") or "baselines",
            "Catalog": params.get("catalog") or "AwsDataCatalog",
        },
        "WorkGroup": params.get("workgroup") or "primary",
    }
    output_location = params.get("outputLocation")
    if output_location:
        kwargs["ResultConfiguration"] = {"OutputLocation": output_location}

    query_id = athena_call(client, "StartQueryExecution", kwargs)["QueryExecutionId"]
    demisto.debug(f"Started Athena query {query_id}")

    deadline = time.time() + timeout
    status = {}
    while True:
        status = athena_call(client, "GetQueryExecution", {"QueryExecutionId": query_id})[
            "QueryExecution"]["Status"]
        state = status["State"]
        if state in TERMINAL_STATES:
            break
        if time.time() > deadline:
            athena_call(client, "StopQueryExecution", {"QueryExecutionId": query_id})
            raise DemistoException(f"Athena query {query_id} timed out after {timeout}s.")
        time.sleep(QUERY_POLL_INTERVAL)

    if status["State"] != "SUCCEEDED":
        reason = status.get("StateChangeReason", status["State"])
        raise DemistoException(f"Athena query {query_id} did not succeed: {reason}")

    rows = []
    token = None
    while True:
        page_kwargs = {"QueryExecutionId": query_id, "MaxResults": 1000}
        if token:
            page_kwargs["NextToken"] = token
        result = athena_call(client, "GetQueryResults", page_kwargs)
        rows += [
            [col.get("VarCharValue") for col in row.get("Data", [])]
            for row in result["ResultSet"]["Rows"]
        ]
        token = result.get("NextToken")
        if not token:
            break

    if not rows:
        return []
    header = rows[0]
    return [dict(zip(header, row)) for row in rows[1:]]


""" GENERAL HELPERS """


def escape_sql_literal(value: str) -> str:
    """Escape a single-quoted SQL string literal (double the quotes)."""
    return str(value).replace("'", "''")


def parse_detected_at(value: str) -> datetime:
    """Parse a detected_at string, tolerating presence/absence of microseconds."""
    value = value.strip()
    for fmt in (DETECTED_AT_FORMAT, FETCH_TIME_FORMAT):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    # last resort: dateparser via CommonServerPython
    parsed = dateparser.parse(value)  # type: ignore[name-defined]  # noqa: F405
    if parsed is None:
        raise DemistoException(f"Could not parse detected_at value: {value}")
    return parsed


def occurred_iso(event_time: str) -> str:
    """Convert an Athena event_time string to an XSOAR 'occurred' ISO-8601 UTC string."""
    if not event_time:
        return ""
    try:
        dt = parse_detected_at(event_time)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return event_time


def map_severity(source_severity) -> float:
    """Map the source rule severity (1-5) to an XSOAR incident severity."""
    return SEVERITY_MAP.get(str(source_severity).strip(), 0)


""" QUERY BUILDERS """


def build_poll_sql(tenant_id: str, status: str, watermark: str) -> str:
    """Build the detections poll query.

    Uses detected_at >= watermark (not strictly greater) so a detection sharing
    the exact boundary timestamp is never skipped; the fetch loop dedupes by
    dedup_key against the ids already seen at that watermark.
    """
    tenant = escape_sql_literal(tenant_id)
    status_esc = escape_sql_literal(status)
    watermark_esc = escape_sql_literal(watermark)
    return f"""
SELECT dedup_key, rule_id, severity, status, identity, entity_type,
       event_time, evidence_count, window_start, window_end,
       event_details, source_event_id, detected_at
FROM   detections
WHERE  tenant_id = '{tenant}'
  AND  status = '{status_esc}'
  AND  detected_at >= TIMESTAMP '{watermark_esc}'
  AND  event_time  > TIMESTAMP '{watermark_esc}' - INTERVAL '1' DAY
ORDER BY detected_at
"""


def build_detection_lookup_sql(dedup_key: str, tenant_id: str = None) -> str:
    dedup_esc = escape_sql_literal(dedup_key)
    tenant_clause = f"  AND tenant_id = '{escape_sql_literal(tenant_id)}'\n" if tenant_id else ""
    return f"""
SELECT dedup_key, rule_id, severity, identity, event_time, event_details, detected_at
FROM   detections
WHERE  dedup_key = '{dedup_esc}'
{tenant_clause}LIMIT 1
"""


def build_drillback_sql(drillback: dict, limit: int = 1000) -> str:
    """Build the raw-log drill-back query from a _drillback recipe.

    A recipe is {table, from, to, like[]}. We prune to the hour partitions the
    window falls in and match each LIKE pattern, then bound by eventtime.
    This mirrors the notebook cell exactly.
    """
    table = drillback["table"]
    frm = drillback["from"][:19]
    to = drillback["to"][:19]
    likes = "".join(
        f"  AND message LIKE '%{escape_sql_literal(p)}%'\n" for p in drillback.get("like", [])
    )

    parts = {(t[:4], t[5:7], t[8:10], t[11:13]) for t in (frm, to)}
    prune = " OR ".join(
        f"(year='{y}' AND month='{m}' AND day='{d}' AND hour='{h}')"
        for y, m, d, h in sorted(parts)
    )

    return f"""
SELECT from_unixtime(TRY_CAST(_time AS double)) AS start_time, message AS rawstring
FROM   {table}
WHERE  ({prune})
{likes}  AND TRY_CAST(regexp_extract(message, 'eventtime=([0-9]+)', 1) AS double) / 1e9
         BETWEEN to_unixtime(timestamp '{frm}') AND to_unixtime(timestamp '{to}')
ORDER BY start_time
LIMIT {int(limit)}
"""


""" INCIDENT BUILDING """


def detection_to_incident(detection: dict) -> dict:
    """Turn one detections row into an XSOAR incident dict."""
    raw = dict(detection)

    # event_details is a JSON string of the analyst variables; parse it so the
    # fields are available in the incident, and stash the drillback recipe.
    event_details = detection.get("event_details")
    labels = {}
    if event_details:
        try:
            labels = json.loads(event_details)
            raw["event_details_parsed"] = labels
            drillback_raw = labels.get("_drillback")
            if drillback_raw:
                raw["drillback"] = json.loads(drillback_raw)
        except (ValueError, TypeError):
            demisto.debug(f"Could not parse event_details for {detection.get('dedup_key')}")

    rule_id = detection.get("rule_id") or "detection"
    identity = detection.get("identity") or ""
    name = f"{rule_id} - {identity}" if identity else rule_id

    return {
        "name": name,
        "occurred": occurred_iso(detection.get("event_time")),
        "severity": map_severity(detection.get("severity")),
        "dbotMirrorId": detection.get("dedup_key"),
        "rawJSON": json.dumps(raw, cls=DatetimeEncoder),
    }


""" COMMAND FUNCTIONS """


def test_module() -> str:
    """Validate connectivity: assume the role and run a trivial Athena call."""
    client = get_client()
    # A cheap, side-effect-free call that still exercises workgroup + role perms.
    athena_call(client, "ListWorkGroups", {})
    params = _params()
    if params.get("isFetch"):
        # Make sure the fetch parameters at least parse.
        first_fetch = params.get("first_fetch") or "3 days"
        if arg_to_datetime(first_fetch) is None:
            return "First fetch timestamp could not be parsed. Use e.g. '3 days' or 'YYYY-MM-DD HH:MM:SS'."
        if not params.get("tenant_id"):
            return "Tenant ID is required when fetching incidents."
    return "ok"


def fetch_incidents():
    """Poll the detections table and create incidents, deduping via last run.

    Watermark = the largest detected_at seen. We store, alongside it, the set of
    dedup_keys already emitted at that exact timestamp, so a detection that lands
    on the boundary is emitted exactly once — never missed, never duplicated.
    """
    params = _params()
    tenant_id = params.get("tenant_id")
    if not tenant_id:
        raise DemistoException("Tenant ID is required when fetching incidents.")
    status = params.get("detection_status") or "ES"
    max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH

    last_run = demisto.getLastRun() or {}
    last_fetch = last_run.get("last_fetch")
    seen_ids = set(last_run.get("seen_ids", []))

    if not last_fetch:
        first_fetch_dt = arg_to_datetime(params.get("first_fetch") or "3 days")
        if first_fetch_dt is None:
            raise DemistoException("Could not parse the first fetch timestamp.")
        last_fetch = first_fetch_dt.strftime(FETCH_TIME_FORMAT)

    client = get_client()
    detections = run_sql(client, build_poll_sql(tenant_id, status, last_fetch))
    # Stable order by detected_at so max-timestamp bookkeeping is correct.
    detections.sort(key=lambda d: d.get("detected_at") or "")

    incidents = []
    max_detected = last_fetch
    for detection in detections:
        detected_at = detection.get("detected_at") or ""
        dedup_key = detection.get("dedup_key")
        if dedup_key in seen_ids:
            continue
        incidents.append(detection_to_incident(detection))
        if detected_at > max_detected:
            max_detected = detected_at
        if len(incidents) >= max_fetch:
            break

    # Rebuild the seen-id set for the new watermark: every dedup_key at the max
    # timestamp we now know about (whether newly emitted or carried over).
    new_seen_ids = {
        d.get("dedup_key") for d in detections if (d.get("detected_at") or "") == max_detected
    }
    if max_detected == last_fetch:
        new_seen_ids |= seen_ids

    demisto.setLastRun({
        "last_fetch": max_detected,
        "seen_ids": [i for i in new_seen_ids if i],
    })
    demisto.incidents(incidents)


def get_raw_event_command(args: dict) -> CommandResults:
    """Drill back to the raw FortiGate log lines for a detection.

    Three ways to specify what to fetch, in order of precedence:
      1. drillback   - a raw {table, from, to, like[]} JSON recipe
      2. dedup_key   - look the detection up and read its _drillback recipe
      3. table/from_time/to_time/like - build the recipe from explicit args
    """
    limit = arg_to_number(args.get("limit")) or 1000
    client = get_client()

    drillback = None
    dedup_key = args.get("dedup_key")

    if args.get("drillback"):
        drillback = json.loads(args["drillback"])
    elif dedup_key:
        tenant_id = args.get("tenant_id") or _params().get("tenant_id")
        rows = run_sql(client, build_detection_lookup_sql(dedup_key, tenant_id))
        if not rows:
            raise DemistoException(f"No detection found for dedup_key '{dedup_key}'.")
        event_details = rows[0].get("event_details")
        if not event_details:
            raise DemistoException(f"Detection '{dedup_key}' has no event_details.")
        labels = json.loads(event_details)
        drillback_raw = labels.get("_drillback")
        if not drillback_raw:
            raise DemistoException(f"Detection '{dedup_key}' has no _drillback recipe.")
        drillback = json.loads(drillback_raw)
    elif args.get("table") and args.get("from_time") and args.get("to_time"):
        like = args.get("like")
        like_list = argToList(like) if like else []
        drillback = {
            "table": args["table"],
            "from": args["from_time"],
            "to": args["to_time"],
            "like": like_list,
        }
    else:
        raise DemistoException(
            "Provide one of: 'drillback' (JSON recipe), 'dedup_key', or "
            "'table' + 'from_time' + 'to_time' (+ optional 'like')."
        )

    sql = build_drillback_sql(drillback, limit=limit)
    demisto.debug(f"Drill-back SQL:\n{sql}")
    raw_events = run_sql(client, sql)

    context = {
        "DedupKey": dedup_key,
        "Drillback": drillback,
        "EventCount": len(raw_events),
        "Events": raw_events,
    }
    readable = tableToMarkdown(
        f"FortiGate raw events ({len(raw_events)})",
        raw_events,
        headers=["start_time", "rawstring"],
    )
    return CommandResults(
        outputs_prefix="AWSS3Athena.RawEvent",
        outputs_key_field="DedupKey",
        outputs=context,
        readable_output=readable,
        raw_response=raw_events,
    )


def get_detections_command(args: dict) -> CommandResults:
    """Run the detections poll on demand (handy for testing / manual triage)."""
    params = _params()
    tenant_id = args.get("tenant_id") or params.get("tenant_id")
    if not tenant_id:
        raise DemistoException("Tenant ID is required.")
    status = args.get("status") or params.get("detection_status") or "ES"

    since_dt = arg_to_datetime(args.get("since") or "1 day")
    if since_dt is None:
        raise DemistoException("Could not parse the 'since' argument.")
    watermark = since_dt.strftime(FETCH_TIME_FORMAT)

    client = get_client()
    detections = run_sql(client, build_poll_sql(tenant_id, status, watermark))

    limit = arg_to_number(args.get("limit"))
    if limit:
        detections = detections[:limit]

    # Parse event_details for context readability.
    for det in detections:
        if det.get("event_details"):
            try:
                det["event_details_parsed"] = json.loads(det["event_details"])
            except (ValueError, TypeError):
                pass

    readable = tableToMarkdown(
        f"Detections since {watermark} ({len(detections)})",
        detections,
        headers=[
            "detected_at", "event_time", "severity", "rule_id",
            "identity", "dedup_key", "evidence_count",
        ],
        removeNull=True,
    )
    return CommandResults(
        outputs_prefix="AWSS3Athena.Detection",
        outputs_key_field="dedup_key",
        outputs=detections,
        readable_output=readable,
        raw_response=detections,
    )


""" MAIN """


def main():
    command = demisto.command()
    LOG(f"Command being called is {command}")
    try:
        if command == "test-module":
            return_results(test_module())
        elif command == "fetch-incidents":
            fetch_incidents()
        elif command == "aws-s3-athena-get-raw-event":
            return_results(get_raw_event_command(demisto.args()))
        elif command == "aws-s3-athena-get-detections":
            return_results(get_detections_command(demisto.args()))
        else:
            raise NotImplementedError(f"Command '{command}' is not implemented.")
    except requests.exceptions.RequestException as e:
        return_error(
            "Could not connect to the AWS endpoint. Please check the region and network.\n"
            f"{e}"
        )
    except Exception as e:  # noqa: BLE001
        return_error(f"Error in AWS S3 Athena (SIEM) integration [{command}]: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
