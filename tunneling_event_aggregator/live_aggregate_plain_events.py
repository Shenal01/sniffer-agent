
# """
# live_aggregate_dns_events.py  (Google Sheets)

# UPDATED:
#   - Only two outcomes: OK and ALERT (no SUSPICIOUS)
#   - Hard override: risk_score >= 50 MUST be ALERT (so it can never be OK)

# Storage:
#   - Reads from tab: plain_raw_query
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
#     from event_aggregator.event_features import compute_event_features, EventFeatureConfig
# except ImportError:
#     from event_features import compute_event_features, EventFeatureConfig  # type: ignore


# DEFAULT_SHEET_ID = "1qBLWgiLiQ54kE3KctVGXh5jm-2U7o7UR3W9XCkeZkK4"
# DEFAULT_SA_JSON = str((PROJECT_ROOT / "firebase" / "firebase-service-account.json").resolve())

# PLAIN_TAB = "plain_raw_query"
# EVENTS_TAB = "events"


# def _log(msg: str) -> None:
#     print(f"[EVENT-PLAIN-SHEETS] {msg}")


# def _is_true(v: Any) -> bool:
#     return str(v).strip().lower() in ("true", "1", "yes", "y")


# def _get_p_fused_from_row(r: Dict[str, Any]) -> Optional[float]:
#     # We support both:
#     # - predictions.fused (float) and predictions.p_fused (float) from your plain fusion script
#     # - any legacy variants if present
#     candidates = [
#         r.get("predictions.fused"),
#         r.get("predictions.p_fused"),
#         r.get("predictions.fused.score"),  # if ever written in dict form
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
#     """
#     UPDATED: Only produces OK or ALERT.
#       - ALERT only if BOTH SLD suspicious and STAT suspicious are true
#       - Otherwise OK
#     """
#     ev = events.copy()

#     sld_suspicious = (ev["max_p"] >= args.sld_max_prob) | (ev["high_frac"] >= args.sld_high_frac)
#     stat_suspicious = (
#         (ev["count"] >= args.stat_min_count)
#         & ((ev["mean_p"] >= args.stat_mean_prob) | (ev["high_frac"] >= args.stat_high_frac))
#     )

#     ev["sld_suspicious"] = sld_suspicious
#     ev["stat_suspicious"] = stat_suspicious

#     final_decision = []
#     for sld_flag, stat_flag in zip(sld_suspicious, stat_suspicious):
#         if bool(sld_flag) and bool(stat_flag):
#             final_decision.append("ALERT")
#         else:
#             final_decision.append("OK")

#     ev["final_decision"] = final_decision
#     ev["is_suspicious"] = ev["final_decision"] == "ALERT"
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
#     """
#     UPDATED: Only OK / ALERT.
#       OK    -> None
#       ALERT -> 'critical' if risk>=90 else 'high'
#     """
#     fd = str(final_decision).upper()
#     if fd == "OK":
#         return None
#     if fd == "ALERT":
#         return "critical" if int(risk_score) >= 90 else "high"
#     return None


# def main() -> None:
#     parser = argparse.ArgumentParser(description="Plain DNS event aggregation (Sheets).")
#     parser.add_argument("--limit", type=int, default=5000)

#     parser.add_argument("--sld_max_prob", type=float, default=0.90)
#     parser.add_argument("--sld_high_frac", type=float, default=0.50)

#     parser.add_argument("--stat_min_count", type=int, default=5)
#     parser.add_argument("--stat_mean_prob", type=float, default=0.70)
#     parser.add_argument("--stat_high_frac", type=float, default=0.60)

#     parser.add_argument("--high_prob_threshold", type=float, default=0.90)
#     parser.add_argument("--bucket_size", type=int, default=60)

#     # NEW: risk floor override (risk >= this => ALERT)
#     parser.add_argument("--risk_alert_floor", type=int, default=50)

#     parser.add_argument("--sheet_id", default=DEFAULT_SHEET_ID)
#     parser.add_argument("--sa_json", default=DEFAULT_SA_JSON)

#     args = parser.parse_args()

#     repo = SheetsRepo(
#         spreadsheet_id=args.sheet_id,
#         service_account_json_path=args.sa_json,
#         tabs=TabNames(plain_raw_query=PLAIN_TAB, doh_raw_query="doh_raw_query", events=EVENTS_TAB),
#     )

#     # Load candidate flows from plain tab
#     flows = repo.rows_as_dicts(PLAIN_TAB)
#     if not flows:
#         _log("No rows in plain_raw_query.")
#         return

#     rows: List[Dict[str, Any]] = []
#     flow_sheet_rows: List[int] = []

#     for r in flows:
#         if str(r.get("component", "")).strip() != "dns_tunneling":
#             continue

#         if not _is_true(r.get("pipeline_status.fusion_done", "")):
#             continue
#         if _is_true(r.get("pipeline_status.event_aggregated", "")):
#             continue

#         p_fused = _get_p_fused_from_row(r)
#         if p_fused is None:
#             continue

#         rows.append(
#             {
#                 "doc_id": r.get("doc_id", ""),  # optional
#                 "timestamp": r.get("timestamp"),
#                 "time_bucket": r.get("time_bucket", 0),
#                 "dns_second_level_domain": r.get("dns_second_level_domain"),
#                 "p_fused": float(p_fused),
#             }
#         )
#         flow_sheet_rows.append(int(r["_sheet_row"]))

#         if args.limit > 0 and len(rows) >= args.limit:
#             break

#     if not rows:
#         _log("No per-query rows needing event aggregation.")
#         return

#     df = pd.DataFrame(rows)

#     cfg = EventFeatureConfig(
#         prob_col="p_fused",
#         high_prob_threshold=args.high_prob_threshold,
#         bucket_size=args.bucket_size,
#     )
#     events = compute_event_features(df, cfg)
#     events = apply_combined_rules(events, args)

#     # Build an index of existing events rows by event_id to support upsert (Firestore merge equivalent)
#     existing_events = repo.rows_as_dicts(EVENTS_TAB)
#     event_id_to_row: Dict[str, int] = {}
#     for er in existing_events:
#         eid = str(er.get("event_id", "")).strip()
#         if eid:
#             event_id_to_row[eid] = int(er["_sheet_row"])

#     # Upsert events
#     upserted = 0
#     appended = 0

#     for _, evr in events.iterrows():
#         time_bucket = int(evr["time_bucket"])
#         sld = str(evr["dns_second_level_domain"])
#         event_id = f"plain_{time_bucket}_{sld}"

#         risk_score = compute_event_risk(
#             int(evr["count"]),
#             float(evr["high_frac"]),
#             float(evr["mean_p"]),
#             float(evr["max_p"]),
#         )

#         # Start from rule-based decision (OK/ALERT), then apply hard risk override
#         final_decision = str(evr["final_decision"]).upper()
#         if int(risk_score) >= int(args.risk_alert_floor):
#             final_decision = "ALERT"

#         is_alert = final_decision == "ALERT"
#         severity = compute_event_severity(final_decision, int(risk_score))

#         doc_data = {
#             "event_id": event_id,
#             "component": "dns_tunneling",
#             "time_bucket": time_bucket,
#             "dns_second_level_domain": sld,
#             "count": int(evr["count"]),
#             "high_frac": float(evr["high_frac"]),
#             "mean_p": float(evr["mean_p"]),
#             "max_p": float(evr["max_p"]),
#             "final_decision": final_decision,
#             "is_suspicious": bool(is_alert),  # same as is_alert now
#             "is_alert": bool(is_alert),
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
#         repo.update_row_fields(PLAIN_TAB, sr, {"pipeline_status": {"event_aggregated": True}})
#         marked += 1

#     _log(
#         f"Events computed={len(events)} (updated={upserted}, appended={appended}); "
#         f"marked_flows={marked} event_aggregated=TRUE."
#     )


# if __name__ == "__main__":
#     main()

#!/usr/bin/env python3
"""
live_aggregate_dns_events.py  (Google Sheets) - PLAIN DNS ONLY

UPDATED (Option A):
  - Event decision is based on proportion of per-query final_decision == ALERT
  - Event ALERT if (count >= 5) and (alert_frac >= 0.3), else OK

Storage:
  - Reads from tab: plain_raw_query
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

# IMPORTANT: keep local import style (works with 'plain-text' folder name)
try:
    from event_aggregator.event_features import compute_event_features, EventAggConfig
except ImportError:
    from event_features import compute_event_features, EventAggConfig  # type: ignore


DEFAULT_SHEET_ID = "1qBLWgiLiQ54kE3KctVGXh5jm-2U7o7UR3W9XCkeZkK4"
DEFAULT_SA_JSON = str((PROJECT_ROOT / "firebase" / "firebase-service-account.json").resolve())

PLAIN_TAB = "plain_raw_query"
EVENTS_TAB = "events"


def _log(msg: str) -> None:
    print(f"[EVENT-PLAIN-SHEETS] {msg}", flush=True)


def _is_true(v: Any) -> bool:
    return str(v).strip().lower() in ("true", "1", "yes", "y")


def _safe_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    s = str(v).strip()
    if s == "":
        return None
    try:
        return float(v)
    except Exception:
        return None


def _get_p_fused_from_row(r: Dict[str, Any]) -> Optional[float]:
    # keep compatibility with your existing fusion outputs
    candidates = [
        r.get("predictions.fused"),
        r.get("predictions.p_fused"),
        r.get("predictions.fused.score"),
    ]
    for c in candidates:
        val = _safe_float(c)
        if val is not None:
            return val
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Plain DNS event aggregation (Sheets) - Option A.")
    parser.add_argument("--limit", type=int, default=5000)

    # Option A parameters
    parser.add_argument("--min_count", type=int, default=5)
    parser.add_argument("--alert_frac", type=float, default=0.30)

    parser.add_argument("--bucket_size", type=int, default=60)

    parser.add_argument("--sheet_id", default=DEFAULT_SHEET_ID)
    parser.add_argument("--sa_json", default=DEFAULT_SA_JSON)

    args = parser.parse_args()

    repo = SheetsRepo(
        spreadsheet_id=args.sheet_id,
        service_account_json_path=args.sa_json,
        tabs=TabNames(plain_raw_query=PLAIN_TAB, doh_raw_query="doh_raw_query", events=EVENTS_TAB),
    )

    flows = repo.rows_as_dicts(PLAIN_TAB)
    if not flows:
        _log("No rows in plain_raw_query.")
        return

    rows: List[Dict[str, Any]] = []
    flow_sheet_rows: List[int] = []

    for r in flows:
        if str(r.get("component", "")).strip() != "dns_tunneling":
            continue

        if not _is_true(r.get("pipeline_status.fusion_done", "")):
            continue
        if _is_true(r.get("pipeline_status.event_aggregated", "")):
            continue

        # We need final_decision to apply Option A
        fd = str(r.get("final_decision", "")).strip()
        if not fd:
            fd = "OK"  # default safe behaviour

        p_fused = _get_p_fused_from_row(r)  # optional stats only

        rows.append(
            {
                "doc_id": r.get("doc_id", ""),  # optional
                "timestamp": r.get("timestamp"),
                "dns_second_level_domain": r.get("dns_second_level_domain", ""),
                "final_decision": fd,
                "p_fused": float(p_fused) if p_fused is not None else None,
            }
        )
        flow_sheet_rows.append(int(r["_sheet_row"]))

        if args.limit > 0 and len(rows) >= args.limit:
            break

    if not rows:
        _log("No per-query rows needing event aggregation.")
        return

    df = pd.DataFrame(rows)

    cfg = EventAggConfig(
        bucket_size=int(args.bucket_size),
        min_count=int(args.min_count),
        alert_frac_threshold=float(args.alert_frac),
    )

    events = compute_event_features(df, cfg)

    # Build an index of existing events rows by event_id to support upsert
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
        sld = str(evr["dns_second_level_domain"])
        event_id = f"plain_{time_bucket}_{sld}"

        final_decision = str(evr["event_decision"]).upper()
        risk_score = int(evr.get("risk_score", 0))
        severity = str(evr.get("severity", "")) if final_decision == "ALERT" else None

        doc_data = {
            "event_id": event_id,
            "component": "dns_tunneling",
            "time_bucket": time_bucket,
            "dns_second_level_domain": sld,

            "count": int(evr["count"]),
            "alert_count": int(evr["alert_count"]),
            "alert_frac": float(evr["alert_frac"]),

            # optional stats
            "mean_p": float(evr["mean_p"]) if "mean_p" in evr and pd.notna(evr["mean_p"]) else "",
            "max_p": float(evr["max_p"]) if "max_p" in evr and pd.notna(evr["max_p"]) else "",
            "std_p": float(evr["std_p"]) if "std_p" in evr and pd.notna(evr["std_p"]) else "",

            "final_decision": final_decision,
            "is_alert": bool(final_decision == "ALERT"),
            "risk_score": risk_score,
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
        repo.update_row_fields(PLAIN_TAB, sr, {"pipeline_status": {"event_aggregated": True}})
        marked += 1

    _log(
        f"Events computed={len(events)} (updated={upserted}, appended={appended}); "
        f"marked_flows={marked} event_aggregated=TRUE."
    )


if __name__ == "__main__":
    main()
