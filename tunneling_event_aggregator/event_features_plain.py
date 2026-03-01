# # event_aggregator/event_features.py

# """
# event_features.py

# Utilities to compute event-level (SLD + time-bucket) features from
# per-query DNS tunneling predictions.

# An "event" = (time_bucket, second_level_domain)

# Output columns (per event):
#     - time_bucket
#     - dns_second_level_domain
#     - count
#     - high_count
#     - high_frac
#     - mean_p
#     - max_p
#     - std_p
# """

# from __future__ import annotations

# from dataclasses import dataclass
# from typing import Optional

# import numpy as np
# import pandas as pd


# def _log(msg: str) -> None:
#     print(f"[EVENT_FE] {msg}")


# def extract_second_level_domain(domain: str) -> str:
#     """
#     Very simple SLD extractor: takes last two labels of the FQDN.
#     Example:
#         "a.b.google.com" -> "google"
#         "google.com"     -> "google"
#         "cdn-cache.tunnel.test" -> "tunnel"

#     This is intentionally simple and deterministic for your dataset.
#     """
#     if not isinstance(domain, str) or not domain:
#         return "unknown"

#     parts = domain.strip(".").split(".")
#     if len(parts) < 2:
#         return domain

#     return parts[-2]


# def add_time_bucket(df: pd.DataFrame, bucket_size: int = 60) -> pd.DataFrame:
#     """
#     Add a 'time_bucket' column based on 'timestamp' (if present).

#     If no 'timestamp' column is found, all rows are mapped to bucket 0.
#     """
#     if "timestamp" not in df.columns:
#         _log("No timestamp column; assigning all queries to time_bucket=0.")
#         df = df.copy()
#         df["time_bucket"] = 0
#         return df

#     df = df.copy()

#     # Parse timestamps; keep timezone if present
#     ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

#     # Convert to epoch seconds; NaT -> NaN
#     epoch = ts.view("int64") // 10**9
#     epoch = pd.Series(epoch).where(ts.notna(), other=np.nan)

#     # If everything is NaN, bucket to 0
#     if epoch.isna().all():
#         _log("All timestamps failed to parse; assigning all queries to time_bucket=0.")
#         df["time_bucket"] = 0
#         return df

#     # Fill missing with min non-missing to keep bucketing consistent
#     min_epoch = int(epoch.dropna().min())
#     epoch = epoch.fillna(min_epoch)

#     df["time_bucket"] = (epoch.astype("int64") // bucket_size) * bucket_size
#     return df


# @dataclass
# class EventFeatureConfig:
#     prob_col: str = "p_tunnel"
#     high_prob_threshold: float = 0.90
#     bucket_size: int = 60


# def compute_event_features(
#     df: pd.DataFrame,
#     config: Optional[EventFeatureConfig] = None,
# ) -> pd.DataFrame:
#     """
#     Compute per-event statistics from per-query predictions.
#     """
#     if config is None:
#         config = EventFeatureConfig()

#     if config.prob_col not in df.columns:
#         raise ValueError(f"Required probability column '{config.prob_col}' not found in DataFrame.")

#     df = df.copy()

#     # --- Ensure we have a domain column -------------------------------------
#     domain_col = None
#     for cand in ("dns_second_level_domain", "dns_domain_name", "dns_qname"):
#         if cand in df.columns:
#             domain_col = cand
#             break

#     if domain_col is None:
#         raise ValueError(
#             "No domain column found. Expected one of: "
#             "'dns_second_level_domain', 'dns_domain_name', 'dns_qname'."
#         )

#     # If only FQDN is present, derive dns_second_level_domain
#     if "dns_second_level_domain" not in df.columns:
#         _log("dns_second_level_domain not found; deriving from DNS name column...")
#         df["dns_second_level_domain"] = df[domain_col].astype(str).apply(extract_second_level_domain)

#     # --- Time bucketing ------------------------------------------------------
#     df = add_time_bucket(df, bucket_size=config.bucket_size)

#     # --- Mark high-probability queries --------------------------------------
#     df["is_high"] = df[config.prob_col] >= config.high_prob_threshold

#     # --- Group by event (time_bucket, SLD) ----------------------------------
#     group_cols = ["time_bucket", "dns_second_level_domain"]
#     grouped = df.groupby(group_cols, as_index=False)

#     events = grouped.agg(
#         count=("is_high", "size"),
#         high_count=("is_high", "sum"),
#         mean_p=(config.prob_col, "mean"),
#         max_p=(config.prob_col, "max"),
#         std_p=(config.prob_col, "std"),
#     )

#     events["std_p"] = events["std_p"].fillna(0.0)
#     events["high_frac"] = np.where(events["count"] > 0, events["high_count"] / events["count"], 0.0)

#     events = events[
#         [
#             "time_bucket",
#             "dns_second_level_domain",
#             "count",
#             "high_count",
#             "high_frac",
#             "mean_p",
#             "max_p",
#             "std_p",
#         ]
#     ]

#     return events

# Exfiltrap-v2.0-prototype1/dns_tunneling/plain-text/event_aggregator/event_features.py

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import numpy as np
import pandas as pd


@dataclass
class EventAggConfig:
    bucket_size: int = 60
    min_count: int = 5
    alert_frac_threshold: float = 0.30


def _log(msg: str) -> None:
    print(f"[EVENT_FE] {msg}", flush=True)


def add_time_bucket(df: pd.DataFrame, bucket_size: int = 60) -> pd.DataFrame:
    """
    Add a numeric epoch-based time_bucket column from 'timestamp' (utc).
    If 'timestamp' missing/unparseable, assigns bucket 0.
    """
    if "timestamp" not in df.columns:
        _log("No timestamp column; assigning all queries to time_bucket=0.")
        df = df.copy()
        df["time_bucket"] = 0
        return df

    df = df.copy()
    ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

    # Fix warning: use astype instead of view
    epoch = (ts.astype("int64") // 10**9).astype("float64")
    epoch = pd.Series(epoch).where(ts.notna(), other=np.nan)

    if epoch.isna().all():
        _log("All timestamps failed to parse; assigning all queries to time_bucket=0.")
        df["time_bucket"] = 0
        return df

    min_epoch = int(epoch.dropna().min())
    epoch = epoch.fillna(min_epoch)

    df["time_bucket"] = (epoch.astype("int64") // int(bucket_size)) * int(bucket_size)
    return df


def compute_event_features(
    df: pd.DataFrame,
    cfg: Optional[EventAggConfig] = None,
) -> pd.DataFrame:
    """
    Option A:
      Event decision uses proportion of per-query final_decision == ALERT.

    REQUIRED columns:
      - timestamp
      - dns_second_level_domain
      - final_decision  (OK/ALERT)

    OPTIONAL:
      - p_fused (kept only for reference; NOT used for decision)
    """
    cfg = cfg or EventAggConfig()

    if df.empty:
        return pd.DataFrame()

    required = {"timestamp", "dns_second_level_domain", "final_decision"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    df = df.copy()
    df = add_time_bucket(df, bucket_size=cfg.bucket_size)

    # Standardize query decision
    fd = df["final_decision"].astype(str).str.strip().str.upper()
    df["is_alert"] = (fd == "ALERT").astype(int)

    group_cols = ["time_bucket", "dns_second_level_domain"]
    grouped = df.groupby(group_cols, as_index=False)

    # Always compute count + alert_count + alert_frac
    events = grouped.agg(
        count=("is_alert", "size"),
        alert_count=("is_alert", "sum"),
    )
    events["alert_frac"] = np.where(events["count"] > 0, events["alert_count"] / events["count"], 0.0)

    # Optional p_fused stats for debugging only
    if "p_fused" in df.columns:
        stats = grouped.agg(
            mean_p=("p_fused", "mean"),
            max_p=("p_fused", "max"),
            std_p=("p_fused", "std"),
        )
        stats["std_p"] = stats["std_p"].fillna(0.0)
        events = events.merge(stats, on=group_cols, how="left")

    # Event decision (your rule)
    events["event_decision"] = "OK"
    mask = (events["count"] >= int(cfg.min_count)) & (events["alert_frac"] >= float(cfg.alert_frac_threshold))
    events.loc[mask, "event_decision"] = "ALERT"

    # Risk score aligned to alert_frac (0..100)
    # Simple and consistent: risk_score = round(100 * alert_frac)
    events["risk_score"] = (100.0 * events["alert_frac"]).round().astype(int)

    # Severity only when ALERT (optional, keep minimal)
    events["severity"] = ""
    events.loc[events["event_decision"] == "ALERT", "severity"] = events.loc[
        events["event_decision"] == "ALERT", "risk_score"
    ].apply(lambda r: "critical" if r >= 90 else ("high" if r >= 70 else ("medium" if r >= 50 else "low")))

    return events
