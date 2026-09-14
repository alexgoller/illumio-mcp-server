import json
import logging
from datetime import datetime, timedelta
import pandas as pd
import mcp.types as types
from illumio import TrafficQuery
from illumio.explorer.trafficanalysis import TrafficQueryFilter
from illumio.util.jsonutils import Reference
from ..pce import run_sync
from .constants import MCP_BUG_MAX_RESULTS, MCP_MAX_RESPONSE_BYTES
from ..log_scrub import ScrubbedArgs

logger = logging.getLogger('illumio_mcp')


def _build_split_response(df, total_pce_flows, total_grouped_rows):
    """Build a compact MCP response using split format (columns + data arrays).

    Split format avoids repeating column names per row — ~60-70% smaller than
    orient='records' for typical traffic data.  Includes metadata so the LLM
    knows whether results were truncated and how much data exists.
    """
    df = df.sort_values('num_connections', ascending=False).reset_index(drop=True)

    def _serialize(frame):
        # NaN → null: astype(object) prevents pandas from coercing None back to NaN
        clean = frame.astype(object).where(frame.notna(), None)
        return json.dumps({
            "total_pce_flows": total_pce_flows,
            "total_rows": total_grouped_rows,
            "returned_rows": len(frame),
            "truncated": len(frame) < total_grouped_rows,
            "columns": frame.columns.tolist(),
            "data": clean.values.tolist(),
        }, default=str)

    payload = _serialize(df)
    if len(payload) <= MCP_MAX_RESPONSE_BYTES:
        return payload

    # Binary search for the largest row count that fits
    lo, hi = 1, len(df)
    best = df.head(1)
    while lo <= hi:
        mid = (lo + hi) // 2
        candidate = df.head(mid)
        size = len(_serialize(candidate))
        if size <= MCP_MAX_RESPONSE_BYTES:
            best = candidate
            lo = mid + 1
        else:
            hi = mid - 1

    logger.warning(f"Truncated response from {len(df)} to {len(best)} rows to fit MCP limit ({MCP_MAX_RESPONSE_BYTES} bytes)")
    return _serialize(best)



# ---------------------------------------------------------------------------
# Filter resolution
# ---------------------------------------------------------------------------

def _label_lookup(pce) -> dict:
    """Map "key=value" -> label href, for resolving human-readable filters."""
    return {
        f"{l.key}={l.value}": l.href
        for l in pce.labels.get(params={'max_results': 10000})
    }


def _resolve_filter_block(block, lookup: dict, unresolved: list):
    """Resolve "key=value" label filters to hrefs, recursively.

    The Explorer API only accepts label HREFs, IP-list HREFs, workload HREFs,
    IPs or FQDNs. Passing "app=vdi" through verbatim makes the PCE reject the
    whole query with "Invalid traffic filter type", which forced callers to run
    get-labels first and paste an href. Resolving here makes the documented
    shorthand actually work and keeps it to one tool call.

    Anything that is not a bare "key=value" string is passed through untouched,
    so hrefs, IPs, FQDNs and already-structured dicts keep working.
    """
    if isinstance(block, list):
        return [_resolve_filter_block(item, lookup, unresolved) for item in block]
    if isinstance(block, str) and "=" in block and not block.startswith("/"):
        href = lookup.get(block.strip())
        if href:
            return {"label": {"href": href}}
        unresolved.append(block)
        return block
    return block


def _resolve_label_filters(pce, arguments: dict) -> list:
    """Resolve label shorthand in every filter argument. Returns unresolved keys."""
    filter_args = ("include_sources", "exclude_sources",
                   "include_destinations", "exclude_destinations")
    if not any(arguments.get(a) for a in filter_args):
        return []

    needs_lookup = any(
        "=" in str(arguments.get(a, "")) for a in filter_args
    )
    if not needs_lookup:
        return []

    unresolved: list = []
    try:
        lookup = _label_lookup(pce)
    except Exception:
        logger.exception("Could not load labels to resolve filter shorthand")
        return []
    for arg in filter_args:
        if arguments.get(arg):
            arguments[arg] = _resolve_filter_block(arguments[arg], lookup, unresolved)
    return unresolved


def _unresolved_error(unresolved: list, pce) -> dict | None:
    """Fail fast on a label filter that matched nothing.

    Forwarding an unresolved "key=value" to the Explorer API makes the PCE
    reject the whole query with "Invalid traffic filter type", which tells the
    caller nothing about which filter was wrong. Naming it here, with the valid
    values for that key, turns a dead end into a correctable mistake.
    """
    if not unresolved:
        return None
    hints = {}
    for item in unresolved:
        key = str(item).split("=", 1)[0].strip()
        try:
            values = sorted({l.value for l in pce.labels.get(
                params={'key': key, 'max_results': 100}) if l.value})
        except Exception:
            values = []
        hints[item] = values[:25] or f"no labels exist with key {key!r}"
    return {
        "error": "unresolved_label_filter",
        "message": ("These filters matched no label in the PCE, so the query was "
                    "not sent. Use key=value with an existing value."),
        "unresolved": unresolved,
        "valid_values": hints,
    }


def _normalise_filter(value):
    """Explorer expects a list of OR-blocks, each a list of AND-conditions.

    An omitted filter must be [[]] ("match anything"), not []. A caller passing
    a flat list like ["app=vdi"] means one block, so wrap it.
    """
    if not value:
        return [[]]
    if isinstance(value, list) and value and not isinstance(value[0], list):
        return [value]
    return value


# ---------------------------------------------------------------------------
# Raw flow retrieval
# ---------------------------------------------------------------------------

def fetch_flows_raw(pce, traffic_query, query_name: str) -> list:
    """Run an async Explorer query and return the raw JSON flow dicts.

    Mirrors PolicyComputeEngine.get_traffic_flows_async, but stops before
    `TrafficFlow.from_json`. The SDK's TrafficNode dataclass only keeps
    ip/label/workload/ip_lists/virtual_server/virtual_service, so fields the
    Explorer API does return -- notably `dst.fqdn` -- are discarded during
    typing and are unrecoverable afterwards. Process and FQDN detail is the
    whole point of this tool, so we keep the raw payload.
    """
    traffic_query.query_name = query_name
    response = pce.post(
        '/traffic_flows/async_queries',
        json=traffic_query,
        headers={'Content-Type': 'application/json',
                 'Prefer': 'respond-async',
                 'Accept': 'application/json'},
        include_org=True,
    )
    response.raise_for_status()
    collection_href = pce._async_poll(response.json()['href'])
    collection = pce.get(collection_href)
    collection.raise_for_status()
    return collection.json()

def to_dataframe(pce, flows):

    label_href_map = {}
    value_href_map = {}
    for l in pce.labels.get(params={'max_results': 10000}):
        label_href_map[l.href] = {"key": l.key, "value": l.value}
        value_href_map["{}={}".format(l.key, l.value)] = l.href

    if not flows:
        logger.warning("Warning: Empty flows list received.")
        return pd.DataFrame()

    series_array = []
    for flow in flows:
        try:
            f = {
                'src_ip': flow.src.ip,
                'src_hostname': flow.src.workload.name if flow.src.workload is not None else None,
                'dst_ip': flow.dst.ip,
                'dst_hostname': flow.dst.workload.name if flow.dst.workload is not None else None,
                'proto': flow.service.proto,
                'port': flow.service.port,
                'process_name': flow.service.process_name,
                'service_name': flow.service.service_name,
                'policy_decision': flow.policy_decision,
                'flow_direction': flow.flow_direction,
                'num_connections': flow.num_connections,
                'first_detected': flow.timestamp_range.first_detected,
                'last_detected': flow.timestamp_range.last_detected,
            }

            # Add IP list names for src and dst
            if flow.src.ip_lists:
                ip_list_names = [ipl.name for ipl in flow.src.ip_lists if hasattr(ipl, 'name') and ipl.name]
                f['src_ip_lists'] = ', '.join(ip_list_names) if ip_list_names else None
            else:
                f['src_ip_lists'] = None

            if flow.dst.ip_lists:
                ip_list_names = [ipl.name for ipl in flow.dst.ip_lists if hasattr(ipl, 'name') and ipl.name]
                f['dst_ip_lists'] = ', '.join(ip_list_names) if ip_list_names else None
            else:
                f['dst_ip_lists'] = None

            # Add src and dst labels from workloads
            if flow.src.workload:
                for l in flow.src.workload.labels:
                    if l.href in label_href_map:
                        key = label_href_map[l.href]['key']
                        value = label_href_map[l.href]['value']
                        f[f'src_{key}'] = value

            if flow.dst.workload:
                for l in flow.dst.workload.labels:
                    if l.href in label_href_map:
                        key = label_href_map[l.href]['key']
                        value = label_href_map[l.href]['value']
                        f[f'dst_{key}'] = value

            series_array.append(f)
        except AttributeError as e:
            logger.debug(f"Error processing flow: {e}")
            logger.debug(f"Flow object: {flow}")

    df = pd.DataFrame(series_array)
    return df



# Sentinel used in place of NaN in group keys. pandas' groupby drops any row
# with a NaN in a grouping column, which silently deleted every flow whose
# destination had no workload -- i.e. exactly the outbound/endpoint traffic
# these tools exist to surface.
NA = "-"


def raw_flows_to_dataframe(pce, raw_flows: list) -> pd.DataFrame:
    """Build a DataFrame from raw Explorer JSON, keeping process and FQDN.

    Unlike the typed path this preserves service.process_name,
    service.windows_service_name, service.user_name and dst.fqdn.
    """
    if not raw_flows:
        logger.warning("Empty flows list received")
        return pd.DataFrame()

    label_href_map = {}
    try:
        for l in pce.labels.get(params={'max_results': 10000}):
            label_href_map[l.href] = {"key": l.key, "value": l.value}
    except Exception:
        logger.exception("Could not load labels; flows will lack label columns")

    def node(side: dict, prefix: str, row: dict) -> None:
        row[f'{prefix}_ip'] = side.get('ip')
        row[f'{prefix}_fqdn'] = side.get('fqdn')
        workload = side.get('workload') or {}
        row[f'{prefix}_hostname'] = workload.get('hostname') or workload.get('name')
        names = [i.get('name') for i in (side.get('ip_lists') or []) if i.get('name')]
        row[f'{prefix}_ip_lists'] = ', '.join(names) if names else None
        for label in (workload.get('labels') or []):
            meta = label_href_map.get(label.get('href'))
            if meta:
                row[f"{prefix}_{meta['key']}"] = meta['value']

    rows = []
    skipped = 0
    for flow in raw_flows:
        try:
            service = flow.get('service') or {}

            def clean(value):
                # The PCE sends "" for an unknown process/user as often as it
                # omits the field. Treating those differently splits one group
                # in two and puts a nameless entry at the top of the ranking.
                if value is None:
                    return None
                text = str(value).strip()
                return text or None

            row = {
                'proto': service.get('proto'),
                'port': service.get('port'),
                'process_name': clean(service.get('process_name')),
                'windows_service_name': clean(service.get('windows_service_name')),
                'user_name': clean(service.get('user_name')),
                'policy_decision': flow.get('policy_decision'),
                'flow_direction': flow.get('flow_direction'),
                'num_connections': flow.get('num_connections') or 0,
                'bytes_in': flow.get('dst_bi'),
                'bytes_out': flow.get('dst_bo'),
                'state': flow.get('state'),
            }

            # Timestamps. The Explorer payload nests these under
            # timestamp_range; FQS uses flat start_time/end_time. Restored
            # after the switch to raw parsing dropped them -- "when did this
            # happen" is unanswerable without them.
            window = flow.get('timestamp_range') or {}
            row['first_detected'] = window.get('first_detected') or flow.get('start_time')
            row['last_detected'] = window.get('last_detected') or flow.get('end_time')

            # Which rule allowed it, and what draft policy would decide.
            # Absent from the Explorer API (verified 0/50 on a live PCE) but
            # present in FQS, so collect defensively rather than assume.
            row['draft_policy_decision'] = flow.get('draft_policy_decision')
            rules = flow.get('rules') or []
            if isinstance(rules, list) and rules:
                hrefs = [r.get('href') for r in rules if isinstance(r, dict) and r.get('href')]
                row['matched_rules'] = ', '.join(hrefs) if hrefs else None
            else:
                row['matched_rules'] = None
            node(flow.get('src') or {}, 'src', row)
            node(flow.get('dst') or {}, 'dst', row)
            rows.append(row)
        except Exception:
            skipped += 1
    if skipped:
        # Never silent: a parse failure used to be a DEBUG line, invisible at
        # the INFO default, so "0 rows from 500 flows" looked like empty data.
        logger.warning("Skipped %d of %d flows that could not be parsed",
                       skipped, len(raw_flows))
    return pd.DataFrame(rows)



# ---------------------------------------------------------------------------
# Grouping dimensions
# ---------------------------------------------------------------------------

# Named dimensions a caller can group by, mapped to the columns that implement
# them. Names are stable and human-meaningful; the columns behind them are an
# implementation detail that can change without breaking the tool contract.
GROUP_DIMENSIONS = {
    "process":     ["process_name"],
    "service_name": ["windows_service_name"],
    "user":        ["user_name"],
    "source":      ["src_ip", "src_hostname"],
    "source_app":  ["src_app", "src_env"],
    "destination": ["dst_ip", "dst_hostname", "dst_fqdn"],
    "dest_app":    ["dst_app", "dst_env"],
    "fqdn":        ["dst_fqdn"],
    "ip_list":     ["src_ip_lists", "dst_ip_lists"],
    "port":        ["port"],
    "proto":       ["proto"],
    "policy":      ["policy_decision"],
    "rule":        ["matched_rules"],
    "direction":   ["flow_direction"],
}

DEFAULT_GROUP_BY = ["source", "destination", "port", "proto", "policy",
                    "process", "service_name", "user", "ip_list"]

# Numeric columns that are summed rather than grouped.
AGGREGATES = {"num_connections": "sum", "bytes_in": "sum", "bytes_out": "sum"}

# Columns carried through grouping by range rather than sum. Without these the
# window collapses and "when did this happen" becomes unanswerable -- the same
# way process_name used to vanish: collected by the parser, dropped by the
# groupby because it was neither a key nor an aggregate. ISO-8601 sorts
# lexicographically, so min/max on the raw strings is correct.
TIME_AGGREGATES = {"first_detected": "min", "last_detected": "max"}


def resolve_group_by(df, group_by=None):
    """Turn dimension names into concrete, present columns.

    Returns (columns, unknown_dimensions). Unknown names are reported rather
    than ignored: silently grouping by something other than what was asked for
    produces a plausible-looking answer to a different question.
    """
    names = group_by or DEFAULT_GROUP_BY
    if isinstance(names, str):
        names = [names]
    columns, unknown = [], []
    for name in names:
        key = str(name).strip().lower()
        if key in GROUP_DIMENSIONS:
            for col in GROUP_DIMENSIONS[key]:
                if col in df.columns and col not in columns:
                    columns.append(col)
        elif key in df.columns:       # allow a raw column name as an escape hatch
            if key not in columns:
                columns.append(key)
        else:
            unknown.append(name)
    return columns, unknown


def group_flows(df, group_by=None):
    """Group a flow frame by named dimensions, summing the numeric columns.

    Fills NaN with the sentinel first: pandas drops any row with a NaN group
    key, which is what silently deleted every outbound flow before.
    """
    columns, unknown = resolve_group_by(df, group_by)
    if not columns:
        return df, [], unknown
    frame = df.copy()
    for col in columns:
        frame[col] = frame[col].fillna(NA)
    aggs = {c: how for c, how in AGGREGATES.items() if c in frame.columns}
    for col in aggs:
        frame[col] = pd.to_numeric(frame[col], errors="coerce").fillna(0)
    for col, how in TIME_AGGREGATES.items():
        if col in frame.columns and col not in columns:
            aggs[col] = how
    grouped = frame.groupby(columns, dropna=False).agg(aggs).reset_index()
    return grouped, columns, unknown

def _endpoint_label(row, prefix: str) -> str:
    """Human-readable identity for one side of a flow.

    Preference order matters for the outbound case: an FQDN is the most useful
    thing to show, then a named IP list, then the workload hostname, then the
    bare IP.
    """
    for col in (f'{prefix}_fqdn', f'{prefix}_ip_lists', f'{prefix}_hostname', f'{prefix}_ip'):
        value = row.get(col)
        if value and value != NA:
            return str(value)
    app = row.get(f'{prefix}_app')
    if app and app != NA:
        env = row.get(f'{prefix}_env')
        return f"{app} ({env})" if env and env != NA else str(app)
    return "unknown"

def _top(frame, by="num_connections", limit=25):
    return frame.sort_values(by, ascending=False).head(limit)


def summarize_traffic_structured(df: pd.DataFrame, *, limit: int = 25) -> dict:
    """Process-aware structured summary of a traffic DataFrame.

    Answers the questions people actually ask of Explorer data, in priority
    order, instead of emitting one flat line per (src, dst, port) group:

      by_process            which binary is talking, to what, on which port
      external_destinations traffic leaving the managed estate
      blocked               what policy is already stopping
      app_to_app            the coarse app-to-app view

    Every grouping fills NaN with a sentinel first. pandas' groupby drops rows
    with a NaN in any group key, which previously deleted every flow whose
    destination had no workload -- i.e. all outbound traffic.
    """
    if df is None or df.empty:
        return {"totals": {"rows": 0, "connections": 0}, "note": "no flows in window"}

    df = df.copy()
    if 'num_connections' not in df.columns:
        df['num_connections'] = 0
    df['num_connections'] = pd.to_numeric(df['num_connections'], errors='coerce').fillna(0)

    for col in df.columns:
        if col != 'num_connections':
            df[col] = df[col].fillna(NA)

    df['src_label'] = df.apply(lambda r: _endpoint_label(r, 'src'), axis=1)
    df['dst_label'] = df.apply(lambda r: _endpoint_label(r, 'dst'), axis=1)

    out: dict = {
        "totals": {
            "rows": int(len(df)),
            "connections": int(df['num_connections'].sum()),
            "distinct_processes": int(
                df.loc[df['process_name'] != NA, 'process_name'].nunique()
            ) if 'process_name' in df.columns else 0,
        }
    }

    # --- by process: the headline view -------------------------------------
    if 'process_name' in df.columns:
        procs = df[~df['process_name'].isin([NA, ''])]
        if not procs.empty:
            grouped = (procs.groupby(['process_name', 'dst_label', 'port', 'proto',
                                      'policy_decision'], dropna=False)['num_connections']
                       .sum().reset_index())
            by_process = []
            for name, chunk in grouped.groupby('process_name'):
                dests = [
                    {"to": r.dst_label, "port": _int(r.port), "proto": _proto(r.proto),
                     "policy": r.policy_decision, "connections": int(r.num_connections)}
                    for r in _top(chunk, limit=10).itertuples()
                ]
                users = sorted({u for u in procs.loc[procs['process_name'] == name,
                                                     'user_name'].unique()
                                if u not in (NA, '')})
                by_process.append({
                    "process": name,
                    "connections": int(chunk['num_connections'].sum()),
                    "destination_count": int(chunk['dst_label'].nunique()),
                    "users": users[:5],
                    "destinations": dests,
                })
            by_process.sort(key=lambda p: p['connections'], reverse=True)
            out['by_process'] = by_process[:limit]
        else:
            out['by_process'] = []
            out['note_process'] = (
                "No process names in this window. The PCE only reports them for "
                "flows observed by a VEN with process visibility enabled."
            )

    # --- traffic leaving the managed estate --------------------------------
    external = df[(df.get('dst_hostname', NA) == NA)]
    if not external.empty:
        cols = ['dst_label', 'port', 'proto', 'policy_decision']
        if 'process_name' in external.columns:
            cols.insert(0, 'process_name')
        ext = (external.groupby(cols, dropna=False)['num_connections']
               .sum().reset_index())
        out['external_destinations'] = [
            {k: (_int(getattr(r, k)) if k == 'port'
                 else _proto(getattr(r, k)) if k == 'proto'
                 else getattr(r, k)) for k in cols}
            | {"connections": int(r.num_connections)}
            for r in _top(ext, limit=limit).itertuples()
        ]

    # --- what policy is stopping -------------------------------------------
    if 'policy_decision' in df.columns:
        blocked = df[df['policy_decision'].isin(['blocked', 'potentially_blocked'])]
        if not blocked.empty:
            cols = ['src_label', 'dst_label', 'port', 'proto', 'policy_decision']
            if 'process_name' in blocked.columns:
                cols.insert(0, 'process_name')
            b = blocked.groupby(cols, dropna=False)['num_connections'].sum().reset_index()
            out['blocked'] = [
                {k: (_int(getattr(r, k)) if k == 'port'
                     else _proto(getattr(r, k)) if k == 'proto'
                     else getattr(r, k)) for k in cols}
                | {"connections": int(r.num_connections)}
                for r in _top(b, limit=limit).itertuples()
            ]

    # --- coarse app-to-app --------------------------------------------------
    if 'src_app' in df.columns or 'dst_app' in df.columns:
        a2a = (df.groupby(['src_label', 'dst_label', 'policy_decision'], dropna=False)
               ['num_connections'].sum().reset_index())
        a2a = a2a[a2a['src_label'] != a2a['dst_label']]
        out['app_to_app'] = [
            {"from": r.src_label, "to": r.dst_label,
             "policy": r.policy_decision, "connections": int(r.num_connections)}
            for r in _top(a2a, limit=limit).itertuples()
        ]

    return out


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


_PROTO_NAMES = {6: "tcp", 17: "udp", 1: "icmp"}


def _proto(value):
    """Explorer reports protocol numerically; 6/17 mean nothing to a reader."""
    try:
        return _PROTO_NAMES.get(int(value), int(value))
    except (TypeError, ValueError):
        return value


def summarize_traffic(df):
    logger.debug(f"Summarizing traffic with dataframe: {df}")

    # Define all possible group columns, including IP list columns and policy decision
    potential_columns = [
        'src_app', 'src_env', 'src_ip_lists',
        'dst_app', 'dst_env', 'dst_ip_lists',
        'proto', 'port', 'policy_decision'
    ]

    # Filter to only use columns that exist in the DataFrame
    group_columns = [col for col in potential_columns if col in df.columns]

    if not group_columns:
        logger.warning("No grouping columns found in DataFrame")
        return "No traffic data available for summarization"

    if df.empty:
        logger.warning("Empty DataFrame received")
        return "No traffic data available for summarization"

    # Fill NaN in IP list columns so groupby works properly
    for col in ['src_ip_lists', 'dst_ip_lists']:
        if col in df.columns:
            df[col] = df[col].fillna('')

    logger.debug(f"Using group columns: {group_columns}")
    logger.debug(f"DataFrame shape before grouping: {df.shape}")
    logger.debug(f"DataFrame columns: {df.columns.tolist()}")
    logger.debug(f"First few rows of DataFrame:\n{df.head()}")

    # Group by available columns
    summary = df.groupby(group_columns)['num_connections'].sum().reset_index()

    logger.debug(f"Summary shape after grouping: {summary.shape}")
    logger.debug(f"Summary columns: {summary.columns.tolist()}")
    logger.debug(f"First few rows of summary:\n{summary.head()}")

    # Sort by number of connections in descending order
    summary = summary.sort_values('num_connections', ascending=False)

    # Convert to a more readable format
    summary_list = []
    for _, row in summary.iterrows():
        # Build source info: prefer app/env labels, fall back to IP list name
        src_info = []
        if 'src_app' in row and row['src_app']:
            src_info.append(row['src_app'])
        if 'src_env' in row and row['src_env']:
            src_info.append(f"({row['src_env']})")
        if not src_info and 'src_ip_lists' in row and row['src_ip_lists']:
            src_info.append(f"[IPList: {row['src_ip_lists']}]")
        src_str = " ".join(src_info) if src_info else "Unknown Source"

        # Build destination info: prefer app/env labels, fall back to IP list name
        dst_info = []
        if 'dst_app' in row and row['dst_app']:
            dst_info.append(row['dst_app'])
        if 'dst_env' in row and row['dst_env']:
            dst_info.append(f"({row['dst_env']})")
        if not dst_info and 'dst_ip_lists' in row and row['dst_ip_lists']:
            dst_info.append(f"[IPList: {row['dst_ip_lists']}]")
        dst_str = " ".join(dst_info) if dst_info else "Unknown Destination"

        if src_str != dst_str:
            port_info = f"port {row['port']}" if 'port' in row else "unknown port"
            proto_info = f"proto {row['proto']}" if 'proto' in row else ""
            policy = row.get('policy_decision', '') if 'policy_decision' in row.index else ''
            policy_str = f" [{policy}]" if policy else ""
            summary_list.append(
                f"From {src_str} to {dst_str} on {port_info} {proto_info}: {row['num_connections']} connections{policy_str}"
            )

    if not summary_list:
        return "No traffic patterns to summarize"

    return "\n".join(summary_list)


def handle_get_traffic_flows(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET TRAFFIC FLOWS CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))

    # assume a default start date of 1 day ago and end date of now
    if 'start_date' not in arguments:
        arguments['start_date'] = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    if 'end_date' not in arguments:
        arguments['end_date'] = datetime.now().strftime('%Y-%m-%d')

    if not arguments or 'start_date' not in arguments or 'end_date' not in arguments:
        error_msg = "Missing required arguments: 'start_date' and 'end_date' are required"
        logger.error(error_msg)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg})
        )]

    logger.debug(f"Start Date: {arguments.get('start_date')}")
    logger.debug(f"End Date: {arguments.get('end_date')}")
    logger.debug(f"Include Sources: {arguments.get('include_sources', [])}")
    logger.debug(f"Exclude Sources: {arguments.get('exclude_sources', [])}")
    logger.debug(f"Include Destinations: {arguments.get('include_destinations', [])}")
    logger.debug(f"Exclude Destinations: {arguments.get('exclude_destinations', [])}")
    logger.debug(f"Include Services: {arguments.get('include_services', [])}")
    logger.debug(f"Exclude Services: {arguments.get('exclude_services', [])}")
    logger.debug(f"Policy Decisions: {arguments.get('policy_decisions', [])}")
    logger.debug(f"Exclude Workloads from IP List: {arguments.get('exclude_workloads_from_ip_list_query', True)}")
    logger.debug(f"Max Results: {arguments.get('max_results', 900)}")
    logger.debug(f"Query Name: {arguments.get('query_name')}")
    logger.debug("=" * 80)

    try:
        pce = ctx.pce

        logger.debug(f"Due to a condition in MCP, max results is set to {MCP_BUG_MAX_RESULTS}")
        arguments['max_results'] = MCP_BUG_MAX_RESULTS

        unresolved = _resolve_label_filters(pce, arguments)
        problem = _unresolved_error(unresolved, pce)
        if problem:
            return [types.TextContent(type="text", text=json.dumps(problem))]

        traffic_query = TrafficQuery.build(
            start_date=arguments['start_date'],
            end_date=arguments['end_date'],
            include_sources=_normalise_filter(arguments.get('include_sources')),
            exclude_sources=arguments.get('exclude_sources', []),
            include_destinations=_normalise_filter(arguments.get('include_destinations')),
            exclude_destinations=arguments.get('exclude_destinations', []),
            include_services=arguments.get('include_services', []),
            exclude_services=arguments.get('exclude_services', []),
            policy_decisions=arguments.get('policy_decisions', []),
            exclude_workloads_from_ip_list_query=arguments.get('exclude_workloads_from_ip_list_query', True),
            max_results=arguments.get('max_results', 10000),
            query_name=arguments.get('query_name', 'mcp-traffic-query')
        )

        all_traffic = fetch_flows_raw(
            pce, traffic_query, arguments.get('query_name', 'mcp-traffic-query'))

        df = raw_flows_to_dataframe(pce, all_traffic)

        if df.empty:
            return [types.TextContent(
                type="text",
                text=json.dumps({"message": "No traffic flows found for the given query parameters",
                                 "start_date": arguments['start_date'],
                                 "end_date": arguments['end_date']})
            )]

        # Group by named dimensions. Defaults keep process / fqdn / user in the
        # key -- they are the whole reason to call this tool -- but a caller can
        # collapse to just what they need, e.g. ["process", "fqdn"].
        df, group_cols, unknown_dims = group_flows(df, arguments.get('group_by'))
        if unknown_dims:
            return [types.TextContent(type="text", text=json.dumps({
                "error": "unknown_group_by",
                "unknown": unknown_dims,
                "valid": sorted(GROUP_DIMENSIONS),
            }))]
        if 'proto' in df.columns:
            df['proto'] = df['proto'].map(_proto)

        total_grouped_rows = len(df)
        payload = _build_split_response(df, total_pce_flows=len(all_traffic), total_grouped_rows=total_grouped_rows)
        del df

        return [types.TextContent(
            type="text",
            text=payload
        )]
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg})
        )]


def handle_get_traffic_flows_summary(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("GET TRAFFIC FLOWS SUMMARY CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
    logger.debug(f"Start Date: {arguments.get('start_date')}")
    logger.debug(f"End Date: {arguments.get('end_date')}")
    logger.debug(f"Include Sources: {arguments.get('include_sources', [])}")
    logger.debug(f"Exclude Sources: {arguments.get('exclude_sources', [])}")
    logger.debug(f"Include Destinations: {arguments.get('include_destinations', [])}")
    logger.debug(f"Exclude Destinations: {arguments.get('exclude_destinations', [])}")
    logger.debug(f"Include Services: {arguments.get('include_services', [])}")
    logger.debug(f"Exclude Services: {arguments.get('exclude_services', [])}")
    logger.debug(f"Policy Decisions: {arguments.get('policy_decisions', [])}")
    logger.debug(f"Exclude Workloads from IP List: {arguments.get('exclude_workloads_from_ip_list_query', True)}")
    logger.debug(f"Max Results: {arguments.get('max_results', 10000)}")
    logger.debug(f"Query Name: {arguments.get('query_name')}")
    logger.debug("=" * 80)

    try:
        pce = ctx.pce

        logger.debug(f"Due to a condition in MCP, max results is set to {MCP_BUG_MAX_RESULTS}")
        max_results = int(arguments.get('max_results', 10000))
        if max_results > MCP_BUG_MAX_RESULTS:
            logger.debug(f"Setting max results to {MCP_BUG_MAX_RESULTS} from original value {max_results}")
            max_results = MCP_BUG_MAX_RESULTS
        arguments['max_results'] = max_results

        unresolved = _resolve_label_filters(pce, arguments)
        problem = _unresolved_error(unresolved, pce)
        if problem:
            return [types.TextContent(type="text", text=json.dumps(problem))]

        query = TrafficQuery.build(
            start_date=arguments['start_date'],
            end_date=arguments['end_date'],
            include_sources=_normalise_filter(arguments.get('include_sources')),
            exclude_sources=arguments.get('exclude_sources', []),
            include_destinations=_normalise_filter(arguments.get('include_destinations')),
            exclude_destinations=arguments.get('exclude_destinations', []),
            include_services=arguments.get('include_services', []),
            exclude_services=arguments.get('exclude_services', []),
            policy_decisions=arguments.get('policy_decisions', []),
            exclude_workloads_from_ip_list_query=arguments.get('exclude_workloads_from_ip_list_query', True),
            max_results=arguments.get('max_results', 10000),
            query_name=arguments.get('query_name', 'mcp-traffic-summary')
        )

        all_traffic = fetch_flows_raw(
            pce, query, arguments.get('query_name', 'mcp-traffic-summary'))

        df = raw_flows_to_dataframe(pce, all_traffic)
        summary = summarize_traffic_structured(df)
        summary['window'] = {'start': arguments['start_date'], 'end': arguments['end_date']}
        summary['totals']['pce_flows'] = len(all_traffic)
        summary['totals']['truncated_at'] = max_results
        if unresolved:
            summary['unresolved_filters'] = unresolved
            summary['unresolved_hint'] = (
                "These label filters matched no label and were sent verbatim. "
                "Use key=value, e.g. app=vdi, or call get-labels for the exact values."
            )

        payload = json.dumps(summary, default=str)
        if len(payload) > MCP_MAX_RESPONSE_BYTES:
            for section in ('app_to_app', 'blocked', 'external_destinations', 'by_process'):
                if section in summary and len(payload) > MCP_MAX_RESPONSE_BYTES:
                    summary[section] = summary[section][:5]
                    summary.setdefault('truncated_sections', []).append(section)
                    payload = json.dumps(summary, default=str)
            logger.warning("Summary truncated to fit the %d byte MCP limit",
                           MCP_MAX_RESPONSE_BYTES)

        return [types.TextContent(type="text", text=payload)]
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(
            type="text",
            text=json.dumps({"error": error_msg})
        )]


def handle_find_unmanaged_traffic(ctx, arguments: dict) -> list:
    logger.debug("=" * 80)
    logger.debug("FIND UNMANAGED TRAFFIC CALLED")
    logger.debug("Arguments received: %s", ScrubbedArgs(arguments))
    logger.debug("=" * 80)

    try:
        pce = ctx.pce

        lookback_days = arguments.get("lookback_days", 30)
        direction = arguments.get("direction", "both")
        min_connections = arguments.get("min_connections", 1)
        top_n = arguments.get("top_n", 50)

        start_date = (datetime.now() - timedelta(days=lookback_days)).strftime('%Y-%m-%d')
        end_date = datetime.now().strftime('%Y-%m-%d')

        traffic_query = TrafficQuery.build(
            start_date=start_date,
            end_date=end_date,
            policy_decisions=["allowed", "potentially_blocked", "blocked"],
            max_results=MCP_BUG_MAX_RESULTS,
            query_name='unmanaged-traffic'
        )

        flows = pce.get_traffic_flows_async(query_name='unmanaged-traffic', traffic_query=traffic_query)
        df = to_dataframe(pce, flows)

        if df.empty:
            return [types.TextContent(type="text", text=json.dumps({
                "message": "No traffic flows found", "lookback_days": lookback_days
            }, indent=2))]

        results = {"unmanaged_sources": [], "unmanaged_destinations": []}

        # Find traffic from unmanaged sources (no src_app label) to managed destinations
        if direction in ("inbound", "both"):
            if 'src_app' in df.columns and 'dst_app' in df.columns:
                unmanaged_src = df[df['src_app'].isna() & df['dst_app'].notna()].copy()
                if not unmanaged_src.empty:
                    group_cols = ['src_ip']
                    if 'dst_app' in unmanaged_src.columns:
                        group_cols.append('dst_app')
                    if 'dst_env' in unmanaged_src.columns:
                        group_cols.append('dst_env')
                    if 'port' in unmanaged_src.columns:
                        group_cols.append('port')
                    if 'proto' in unmanaged_src.columns:
                        group_cols.append('proto')

                    grouped = unmanaged_src.groupby(group_cols)['num_connections'].sum().reset_index()
                    grouped = grouped[grouped['num_connections'] >= min_connections]
                    grouped = grouped.sort_values('num_connections', ascending=False).head(top_n)

                    for _, row in grouped.iterrows():
                        entry = {
                            "src_ip": row.get('src_ip', ''),
                            "dst_app": row.get('dst_app', ''),
                            "dst_env": row.get('dst_env', ''),
                            "port": int(row['port']) if 'port' in row and pd.notna(row['port']) else None,
                            "proto": int(row['proto']) if 'proto' in row and pd.notna(row['proto']) else None,
                            "connections": int(row['num_connections'])
                        }
                        results["unmanaged_sources"].append(entry)

        # Find traffic to unmanaged destinations (no dst_app label) from managed sources
        if direction in ("outbound", "both"):
            if 'src_app' in df.columns and 'dst_app' in df.columns:
                unmanaged_dst = df[df['dst_app'].isna() & df['src_app'].notna()].copy()
                if not unmanaged_dst.empty:
                    group_cols = ['dst_ip']
                    if 'src_app' in unmanaged_dst.columns:
                        group_cols.append('src_app')
                    if 'src_env' in unmanaged_dst.columns:
                        group_cols.append('src_env')
                    if 'port' in unmanaged_dst.columns:
                        group_cols.append('port')
                    if 'proto' in unmanaged_dst.columns:
                        group_cols.append('proto')

                    grouped = unmanaged_dst.groupby(group_cols)['num_connections'].sum().reset_index()
                    grouped = grouped[grouped['num_connections'] >= min_connections]
                    grouped = grouped.sort_values('num_connections', ascending=False).head(top_n)

                    for _, row in grouped.iterrows():
                        entry = {
                            "dst_ip": row.get('dst_ip', ''),
                            "src_app": row.get('src_app', ''),
                            "src_env": row.get('src_env', ''),
                            "port": int(row['port']) if 'port' in row and pd.notna(row['port']) else None,
                            "proto": int(row['proto']) if 'proto' in row and pd.notna(row['proto']) else None,
                            "connections": int(row['num_connections'])
                        }
                        results["unmanaged_destinations"].append(entry)

        result = {
            "lookback_days": lookback_days,
            "direction_filter": direction,
            "min_connections": min_connections,
            "unmanaged_source_count": len(results["unmanaged_sources"]),
            "unmanaged_destination_count": len(results["unmanaged_destinations"]),
            "unmanaged_sources": results["unmanaged_sources"],
            "unmanaged_destinations": results["unmanaged_destinations"],
            "recommendation": (
                "Unmanaged traffic represents policy blind spots. Consider: "
                "1) Creating IP lists for known external services, "
                "2) Deploying VEN agents on unmanaged workloads, "
                "3) Adding rules for legitimate unmanaged traffic sources."
            )
        }

        return [types.TextContent(type="text", text=json.dumps(result, indent=2))]

    except Exception as e:
        error_msg = f"Failed to find unmanaged traffic: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}, indent=2))]


def _is_external(row) -> bool:
    """True when the destination is not a workload this PCE manages.

    Egress is defined by the absence of a managed destination workload, not by
    RFC1918 ranges: a flow to an unmanaged internal host is just as interesting
    as one to the internet, and an IP-list name alone does not tell us which.
    """
    hostname = row.get('dst_hostname')
    return hostname in (None, NA, '') or pd.isna(hostname)


def handle_discover_process_egress(ctx, arguments: dict) -> list:
    """Which processes talk to destinations outside the managed estate.

    A focused answer to the shadow-IT question. get-traffic-flows can produce
    the same data with group_by, but the curation is the value here: external
    only, FQDN preferred over IP, ranked, and annotated with whether policy is
    actually permitting it.
    """
    logger.debug("DISCOVER PROCESS EGRESS CALLED: %s", ScrubbedArgs(arguments))

    lookback = int(arguments.get('lookback_days', 7))
    arguments.setdefault('start_date',
                         (datetime.now() - timedelta(days=lookback)).strftime('%Y-%m-%d'))
    arguments.setdefault('end_date', datetime.now().strftime('%Y-%m-%d'))

    try:
        pce = ctx.pce
        unresolved = _resolve_label_filters(pce, arguments)
        problem = _unresolved_error(unresolved, pce)
        if problem:
            return [types.TextContent(type="text", text=json.dumps(problem))]

        max_results = min(int(arguments.get('max_results', MCP_BUG_MAX_RESULTS)),
                          MCP_BUG_MAX_RESULTS)
        query = TrafficQuery.build(
            start_date=arguments['start_date'],
            end_date=arguments['end_date'],
            include_sources=_normalise_filter(arguments.get('include_sources')),
            exclude_sources=arguments.get('exclude_sources', []),
            include_destinations=_normalise_filter(arguments.get('include_destinations')),
            exclude_destinations=arguments.get('exclude_destinations', []),
            include_services=arguments.get('include_services', []),
            exclude_services=arguments.get('exclude_services', []),
            policy_decisions=arguments.get('policy_decisions', []),
            exclude_workloads_from_ip_list_query=False,   # egress lives in IP lists
            max_results=max_results,
            query_name=arguments.get('query_name', 'mcp-process-egress'),
        )
        raw = fetch_flows_raw(pce, query, arguments.get('query_name', 'mcp-process-egress'))
        df = raw_flows_to_dataframe(pce, raw)
        if df.empty:
            return [types.TextContent(type="text", text=json.dumps({
                "message": "No traffic flows found in the specified window",
                "window": {"start": arguments['start_date'], "end": arguments['end_date']},
                "pce_flows": len(raw),
            }))]

        external = df[df.apply(_is_external, axis=1)]
        wanted = arguments.get('process')
        if wanted:
            needles = [wanted] if isinstance(wanted, str) else list(wanted)
            mask = external['process_name'].fillna('').str.lower().apply(
                lambda name: any(n.lower() in name for n in needles if n))
            external = external[mask]

        if arguments.get('only_named_processes', True):
            external = external[external['process_name'].notna()
                                & (external['process_name'] != '')]

        if external.empty:
            return [types.TextContent(type="text", text=json.dumps({
                "message": "No egress flows matched",
                "window": {"start": arguments['start_date'], "end": arguments['end_date']},
                "pce_flows": len(raw),
                "hint": ("The PCE only reports process names for flows seen by a VEN with "
                         "process visibility enabled. Set only_named_processes=false to "
                         "include flows with no process attribution."),
            }))]

        grouped, _, _ = group_flows(external, ["process", "user", "destination",
                                               "port", "proto", "policy", "rule"])
        grouped = grouped.sort_values('num_connections', ascending=False)

        limit = int(arguments.get('limit', 50))
        findings, by_process = [], {}
        for row in grouped.head(limit).to_dict('records'):
            target = _endpoint_label(row, 'dst')
            allowed = row.get('policy_decision') == 'allowed'
            finding = {
                "process": row.get('process_name'),
                "user": row.get('user_name') if row.get('user_name') != NA else None,
                "destination": target,
                "resolved_by_name": bool(row.get('dst_fqdn') not in (None, NA, '')),
                "port": _int(row.get('port')),
                "proto": _proto(row.get('proto')),
                "policy_decision": row.get('policy_decision'),
                "permitted_today": allowed,
                "connections": int(row.get('num_connections') or 0),
            }
            if row.get('matched_rules') not in (None, NA, ''):
                finding["matched_rule"] = row['matched_rules']
            findings.append(finding)
            by_process.setdefault(finding["process"], set()).add(target)

        return [types.TextContent(type="text", text=json.dumps({
            "window": {"start": arguments['start_date'], "end": arguments['end_date']},
            "totals": {
                "pce_flows": len(raw),
                "egress_rows": int(len(external)),
                "distinct_processes": len(by_process),
                "returned": len(findings),
                "truncated": len(grouped) > limit,
            },
            "processes": [
                {"process": name, "external_destinations": sorted(dests)[:20]}
                for name, dests in sorted(by_process.items(),
                                          key=lambda kv: -len(kv[1]))
            ],
            "findings": findings,
            "note": ("Egress means the destination is not a workload managed by this PCE. "
                     "permitted_today reflects current policy, so a true value on an "
                     "unexpected destination is the interesting case."),
        }, default=str))]
    except Exception as e:
        error_msg = f"Failed in PCE operation: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [types.TextContent(type="text", text=json.dumps({"error": error_msg}))]
