# #!/usr/bin/env python3
# """
# live_aggregate_doh_events.py (Google Sheets)

# NEW (carried over):
#   - Writes event-level risk_score + severity
#   - Event severity mapping (your requirement):
#       OK         -> severity = null
#       SUSPICIOUS -> medium if risk>=85 else low
#       ALERT      -> critical if risk>=90 else high

# Storage:
#   - Reads from tab: doh_raw_query
#   - Writes/Upserts into tab: events
#   - Marks flows event_aggregated by updating: pipeline_status.event_aggregated = TRUE
# """

# import sys
# from pathlib import Path

# THIS_FILE = Path(__file__).resolve()
# PROJECT_ROOT = THIS_FILE.parents[3]
# if str(PROJECT_ROOT) not in sys.path:
#     sys.path.insert(0, str(PROJECT_ROOT))

# import argparse
# from typing import List, Dict, Any, Optional

# import pandas as pd

# from dns_tunneling.storage.sheets_repo import SheetsRepo, TabNames  # type: ignore

# try:
#     from event_aggregator.event_features_doh import compute_event_features_doh, DoHEventFeatureConfig
# except ImportError:
#     from event_features_doh import compute_event_features_doh, DoHEventFeatureConfig  # type: ignore


# DEFAULT_SHEET_ID = "1qBLWgiLiQ54kE3KctVGXh5jm-2U7o7UR3W9XCkeZkK4"
# DEFAULT_SA_JSON = str((PROJECT_ROOT / "firebase" / "firebase-service-account.json").resolve())

# DOH_TAB = "doh_raw_query"
# EVENTS_TAB = "events"


# def _log(msg: str) -> None:
#     print(f"[EVENT-DOH-SHEETS] {msg}")


# def _is_true(v: Any) -> bool:
#     return str(v).strip().lower() in ("true", "1", "yes", "y")


# def _get_doh_p_fused_from_row(r: Dict[str, Any]) -> Optional[float]:
#     # DoH fusion writes predictions.fused.score (primary). Also accept predictions.fused if present.
#     candidates = [
#         r.get("predictions.fused.score"),
#         r.get("predictions.fused"),  # if ever written as float
#         r.get("predictions.fused_score"),
#     ]
#     for c in candidates:
#         if c is None:
#             continue
#         s = str(c).strip()
#         if s == "":
#             continue
#         try:
#             return float(c)
#         except Exception:
#             continue
#     return None


# def apply_combined_rules(events: pd.DataFrame, args: argparse.Namespace) -> pd.DataFrame:
#     ev = events.copy()

#     endpoint_suspicious = (ev["max_p"] >= args.sld_max_prob) | (ev["high_frac"] >= args.sld_high_frac)
#     stat_suspicious = (
#         (ev["count"] >= args.stat_min_count)
#         & ((ev["mean_p"] >= args.stat_mean_prob) | (ev["high_frac"] >= args.stat_high_frac))
#     )

#     ev["endpoint_suspicious"] = endpoint_suspicious
#     ev["stat_suspicious"] = stat_suspicious

#     final_decision = []
#     for e_flag, s_flag in zip(endpoint_suspicious, stat_suspicious):
#         if e_flag and s_flag:
#             final_decision.append("ALERT")
#         elif e_flag and not s_flag:
#             final_decision.append("SUSPICIOUS")
#         else:
#             final_decision.append("OK")

#     ev["final_decision"] = final_decision
#     ev["is_suspicious"] = ev["final_decision"].isin(["ALERT", "SUSPICIOUS"])
#     ev["is_alert"] = ev["final_decision"] == "ALERT"
#     return ev


# def compute_event_risk(count: int, high_frac: float, mean_p: float, max_p: float) -> int:
#     base = 100.0 * float(max_p)
#     bonus = 0.0
#     if float(high_frac) >= 0.60:
#         bonus += 7.0
#     elif float(high_frac) >= 0.40:
#         bonus += 4.0
#     if int(count) >= 20:
#         bonus += 6.0
#     elif int(count) >= 10:
#         bonus += 3.0
#     if float(mean_p) >= 0.80:
#         bonus += 3.0
#     return int(round(max(0.0, min(100.0, base + bonus))))


# def compute_event_severity(final_decision: str, risk_score: int):
#     fd = str(final_decision).upper()
#     if fd == "OK":
#         return None
#     if fd == "SUSPICIOUS":
#         return "medium" if int(risk_score) >= 85 else "low"
#     if fd == "ALERT":
#         return "critical" if int(risk_score) >= 90 else "high"
#     return None


# def main() -> None:
#     parser = argparse.ArgumentParser(description="DoH event aggregation (Sheets).")
#     parser.add_argument("--limit", type=int, default=5000)

#     parser.add_argument("--sld_max_prob", type=float, default=0.90)
#     parser.add_argument("--sld_high_frac", type=float, default=0.50)

#     parser.add_argument("--stat_min_count", type=int, default=5)
#     parser.add_argument("--stat_mean_prob", type=float, default=0.70)
#     parser.add_argument("--stat_high_frac", type=float, default=0.60)

#     parser.add_argument("--high_prob_threshold", type=float, default=0.90)
#     parser.add_argument("--bucket_size", type=int, default=60)

#     parser.add_argument("--sheet_id", default=DEFAULT_SHEET_ID)
#     parser.add_argument("--sa_json", default=DEFAULT_SA_JSON)

#     args = parser.parse_args()

#     repo = SheetsRepo(
#         spreadsheet_id=args.sheet_id,
#         service_account_json_path=args.sa_json,
#         tabs=TabNames(plain_raw_query="plain_raw_query", doh_raw_query=DOH_TAB, events=EVENTS_TAB),
#     )

#     flows = repo.rows_as_dicts(DOH_TAB)
#     if not flows:
#         _log("No rows in doh_raw_query.")
#         return

#     rows: List[Dict[str, Any]] = []
#     flow_sheet_rows: List[int] = []

#     for r in flows:
#         if str(r.get("component", "")).strip() != "dns_tunneling_doh":
#             continue

#         if not _is_true(r.get("pipeline_status.fusion_done", "")):
#             continue
#         if _is_true(r.get("pipeline_status.event_aggregated", "")):
#             continue

#         p_fused = _get_doh_p_fused_from_row(r)
#         if p_fused is None:
#             continue

#         rows.append(
#             {
#                 "doc_id": r.get("doc_id", ""),  # optional
#                 "timestamp": r.get("timestamp"),
#                 "client_ip": r.get("client_ip", r.get("src_ip", "unknown")),
#                 "server_ip": r.get("server_ip", r.get("dst_ip", "unknown")),
#                 "p_fused": float(p_fused),
#             }
#         )
#         flow_sheet_rows.append(int(r["_sheet_row"]))

#         if args.limit > 0 and len(rows) >= args.limit:
#             break

#     if not rows:
#         _log("No DoH per-flow rows needing event aggregation.")
#         return

#     df = pd.DataFrame(rows)

#     cfg = DoHEventFeatureConfig(
#         prob_col="p_fused",
#         high_prob_threshold=args.high_prob_threshold,
#         bucket_size=args.bucket_size,
#     )
#     events = compute_event_features_doh(df, cfg)
#     events = apply_combined_rules(events, args)

#     # Upsert support (Firestore merge equivalent)
#     existing_events = repo.rows_as_dicts(EVENTS_TAB)
#     event_id_to_row: Dict[str, int] = {}
#     for er in existing_events:
#         eid = str(er.get("event_id", "")).strip()
#         if eid:
#             event_id_to_row[eid] = int(er["_sheet_row"])

#     upserted = 0
#     appended = 0

#     for _, evr in events.iterrows():
#         time_bucket = int(evr["time_bucket"])
#         doh_key = str(evr["doh_key"])
#         event_id = f"doh_{time_bucket}_{doh_key}"

#         risk_score = compute_event_risk(int(evr["count"]), float(evr["high_frac"]), float(evr["mean_p"]), float(evr["max_p"]))
#         severity = compute_event_severity(str(evr["final_decision"]), risk_score)

#         doc_data: Dict[str, Any] = {
#             "event_id": event_id,
#             "component": "dns_tunneling_doh",
#             "time_bucket": time_bucket,
#             "client_ip": str(evr["client_ip"]),
#             "server_ip": str(evr["server_ip"]),
#             "doh_key": doh_key,
#             "count": int(evr["count"]),
#             "high_frac": float(evr["high_frac"]),
#             "mean_p": float(evr["mean_p"]),
#             "max_p": float(evr["max_p"]),
#             "final_decision": str(evr["final_decision"]),
#             "is_suspicious": bool(evr["is_suspicious"]),
#             "is_alert": bool(evr["is_alert"]),
#             "risk_score": int(risk_score),
#             "severity": severity,
#         }

#         if event_id in event_id_to_row:
#             repo.update_row_fields(EVENTS_TAB, event_id_to_row[event_id], doc_data)
#             upserted += 1
#         else:
#             repo.append_document(EVENTS_TAB, doc_data)
#             appended += 1

#     # Mark flows aggregated
#     marked = 0
#     for sr in flow_sheet_rows:
#         repo.update_row_fields(DOH_TAB, sr, {"pipeline_status": {"event_aggregated": True}})
#         marked += 1

#     _log(f"Events computed={len(events)} (updated={upserted}, appended={appended}); marked_flows={marked} event_aggregated=TRUE.")


# if __name__ == "__main__":
#     main()


#!/usr/bin/env python3
"""
live_aggregate_doh_events.py (Google Sheets)

UPDATED (minimal changes):
  - Only 2 final decisions now: OK or ALERT (removed SUSPICIOUS)
  - Slightly more sensitive thresholds (so confirmed malicious buckets don't stay OK)
  - Added a simple event-level risk override (uses existing compute_event_risk)

Severity mapping (updated):
  OK    -> severity = null
  ALERT -> critical if risk>=90 else high

Storage:
  - Reads from tab: doh_raw_query
  - Writes/Upserts into tab: events
  - Marks flows event_aggregated by updating: pipeline_status.event_aggregated = TRUE
"""

import sys
from pathlib import Path

THIS_FILE = Path(__file__).resolve()
PROJECT_ROOT = THIS_FILE.parents[3]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import argparse
from typing import List, Dict, Any, Optional

import pandas as pd

from dns_tunneling.storage.sheets_repo import SheetsRepo, TabNames  # type: ignore

try:
    from event_aggregator.event_features_doh import compute_event_features_doh, DoHEventFeatureConfig
except ImportError:
    from event_features_doh import compute_event_features_doh, DoHEventFeatureConfig  # type: ignore


DEFAULT_SHEET_ID = "1qBLWgiLiQ54kE3KctVGXh5jm-2U7o7UR3W9XCkeZkK4"
DEFAULT_SA_JSON = str((PROJECT_ROOT / "firebase" / "firebase-service-account.json").resolve())

DOH_TAB = "doh_raw_query"
EVENTS_TAB = "events"


def _log(msg: str) -> None:
    print(f"[EVENT-DOH-SHEETS] {msg}")


def _is_true(v: Any) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes", "y")


def _get_doh_p_fused_from_row(r: Dict[str, Any]) -> Optional[float]:
    # DoH fusion writes predictions.fused.score (primary). Also accept predictions.fused if present.
    candidates = [
        r.get("predictions.fused.score"),
        r.get("predictions.fused"),  # if ever written as float
        r.get("predictions.fused_score"),
    ]
    for c in candidates:
        if c is None:
            continue
        s = str(c).strip()
        if s == "":
            continue
        try:
            return float(c)
        except Exception:
            continue
    return None


def compute_event_risk(count: int, high_frac: float, mean_p: float, max_p: float) -> int:
    base = 100.0 * float(max_p)
    bonus = 0.0
    if float(high_frac) >= 0.60:
        bonus += 7.0
    elif float(high_frac) >= 0.40:
        bonus += 4.0
    if int(count) >= 20:
        bonus += 6.0
    elif int(count) >= 10:
        bonus += 3.0
    if float(mean_p) >= 0.80:
        bonus += 3.0
    return int(round(max(0.0, min(100.0, base + bonus))))


def apply_combined_rules(events: pd.DataFrame, args: argparse.Namespace) -> pd.DataFrame:
    ev = events.copy()

    # Existing gates (unchanged)
    endpoint_suspicious = (ev["max_p"] >= args.sld_max_prob) | (ev["high_frac"] >= args.sld_high_frac)
    stat_suspicious = (
        (ev["count"] >= args.stat_min_count)
        & ((ev["mean_p"] >= args.stat_mean_prob) | (ev["high_frac"] >= args.stat_high_frac))
    )

    ev["endpoint_suspicious"] = endpoint_suspicious
    ev["stat_suspicious"] = stat_suspicious

    # NEW (minimal): compute risk_score here so decision can use it
    ev["risk_score"] = ev.apply(
        lambda r: compute_event_risk(int(r["count"]), float(r["high_frac"]), float(r["mean_p"]), float(r["max_p"])),
        axis=1,
    )

    # NEW (minimal): only 2 outcomes: OK / ALERT
    # Alert if:
    #   (endpoint AND statistical) OR (risk_score override with minimal count)
    alert_flag = (endpoint_suspicious & stat_suspicious) | (
        (ev["count"].astype(int) >= int(args.risk_min_count)) & (ev["risk_score"].astype(int) >= int(args.risk_alert))
    )

    ev["final_decision"] = alert_flag.map(lambda x: "ALERT" if bool(x) else "OK")
    ev["is_suspicious"] = ev["final_decision"].eq("ALERT")
    ev["is_alert"] = ev["final_decision"].eq("ALERT")
    return ev


def compute_event_severity(final_decision: str, risk_score: int):
    fd = str(final_decision).upper()
    if fd == "OK":
        return None
    if fd == "ALERT":
        return "critical" if int(risk_score) >= 90 else "high"
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="DoH event aggregation (Sheets).")
    parser.add_argument("--limit", type=int, default=5000)

    # Tweaked a bit more sensitive (from your earlier results)
    parser.add_argument("--sld_max_prob", type=float, default=0.78)
    parser.add_argument("--sld_high_frac", type=float, default=0.30)

    parser.add_argument("--stat_min_count", type=int, default=5)
    parser.add_argument("--stat_mean_prob", type=float, default=0.55)
    parser.add_argument("--stat_high_frac", type=float, default=0.40)

    # What counts as "high" for high_frac in event_features
    parser.add_argument("--high_prob_threshold", type=float, default=0.80)
    parser.add_argument("--bucket_size", type=int, default=60)

    # NEW (minimal): risk override (so malicious buckets with max_p~0.74–0.81 don't stay OK)
    parser.add_argument("--risk_alert", type=int, default=74)
    parser.add_argument("--risk_min_count", type=int, default=2)

    parser.add_argument("--sheet_id", default=DEFAULT_SHEET_ID)
    parser.add_argument("--sa_json", default=DEFAULT_SA_JSON)

    args = parser.parse_args()

    repo = SheetsRepo(
        spreadsheet_id=args.sheet_id,
        service_account_json_path=args.sa_json,
        tabs=TabNames(plain_raw_query="plain_raw_query", doh_raw_query=DOH_TAB, events=EVENTS_TAB),
    )

    flows = repo.rows_as_dicts(DOH_TAB)
    if not flows:
        _log("No rows in doh_raw_query.")
        return

    rows: List[Dict[str, Any]] = []
    flow_sheet_rows: List[int] = []

    for r in flows:
        if str(r.get("component", "")).strip() != "dns_tunneling_doh":
            continue

        if not _is_true(r.get("pipeline_status.fusion_done", "")):
            continue
        if _is_true(r.get("pipeline_status.event_aggregated", "")):
            continue

        p_fused = _get_doh_p_fused_from_row(r)
        if p_fused is None:
            continue

        rows.append(
            {
                "doc_id": r.get("doc_id", ""),  # optional
                "timestamp": r.get("timestamp"),
                "client_ip": r.get("client_ip", r.get("src_ip", "unknown")),
                "server_ip": r.get("server_ip", r.get("dst_ip", "unknown")),
                "p_fused": float(p_fused),
            }
        )
        flow_sheet_rows.append(int(r["_sheet_row"]))

        if args.limit > 0 and len(rows) >= args.limit:
            break

    if not rows:
        _log("No DoH per-flow rows needing event aggregation.")
        return

    df = pd.DataFrame(rows)

    cfg = DoHEventFeatureConfig(
        prob_col="p_fused",
        high_prob_threshold=args.high_prob_threshold,
        bucket_size=args.bucket_size,
    )
    events = compute_event_features_doh(df, cfg)
    events = apply_combined_rules(events, args)

    # Upsert support (Firestore merge equivalent)
    existing_events = repo.rows_as_dicts(EVENTS_TAB)
    event_id_to_row: Dict[str, int] = {}
    for er in existing_events:
        eid = str(er.get("event_id", "")).strip()
        if eid:
            event_id_to_row[eid] = int(er["_sheet_row"])

    upserted = 0
    appended = 0

    for _, evr in events.iterrows():
        time_bucket = int(evr["time_bucket"])
        doh_key = str(evr["doh_key"])
        event_id = f"doh_{time_bucket}_{doh_key}"

        # Now risk_score already computed in apply_combined_rules()
        risk_score = int(evr.get("risk_score", 0))
        severity = compute_event_severity(str(evr["final_decision"]), risk_score)

        doc_data: Dict[str, Any] = {
            "event_id": event_id,
            "component": "dns_tunneling_doh",
            "time_bucket": time_bucket,
            "client_ip": str(evr["client_ip"]),
            "server_ip": str(evr["server_ip"]),
            "doh_key": doh_key,
            "count": int(evr["count"]),
            "high_frac": float(evr["high_frac"]),
            "mean_p": float(evr["mean_p"]),
            "max_p": float(evr["max_p"]),
            "final_decision": str(evr["final_decision"]),
            "is_suspicious": bool(evr["is_suspicious"]),
            "is_alert": bool(evr["is_alert"]),
            "risk_score": int(risk_score),
            "severity": severity,
        }

        if event_id in event_id_to_row:
            repo.update_row_fields(EVENTS_TAB, event_id_to_row[event_id], doc_data)
            upserted += 1
        else:
            repo.append_document(EVENTS_TAB, doc_data)
            appended += 1

    # Mark flows aggregated
    marked = 0
    for sr in flow_sheet_rows:
        repo.update_row_fields(DOH_TAB, sr, {"pipeline_status": {"event_aggregated": True}})
        marked += 1

    _log(
        f"Events computed={len(events)} (updated={upserted}, appended={appended}); "
        f"marked_flows={marked} event_aggregated=TRUE."
    )


if __name__ == "__main__":
    main()
