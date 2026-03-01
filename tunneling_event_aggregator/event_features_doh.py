#!/usr/bin/env python3
"""
event_features_doh.py

Compute event-level features for DoH using grouping:
    (time_bucket, client_ip, server_ip)

Inputs per flow:
    - timestamp (recommended)
    - client_ip/src_ip
    - server_ip/dst_ip
    - p_fused (we will use predictions.fused.score as p_fused)

Outputs per event (same columns as plain to reuse combined rules):
    - time_bucket
    - doh_key              (string key client_ip|server_ip)
    - client_ip
    - server_ip
    - count
    - high_count
    - high_frac
    - mean_p
    - max_p
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import numpy as np
import pandas as pd


def _log(msg: str) -> None:
    print(f"[DOH_EVENT_FE] {msg}")


@dataclass
class DoHEventFeatureConfig:
    prob_col: str = "p_fused"
    high_prob_threshold: float = 0.90
    bucket_size: int = 60


def _add_time_bucket(df: pd.DataFrame, bucket_size: int) -> pd.DataFrame:
    df = df.copy()

    if "timestamp" not in df.columns:
        _log("No timestamp column; assigning time_bucket=0 for all.")
        df["time_bucket"] = 0
        return df

    ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    epoch = ts.view("int64") // 10**9
    epoch = pd.Series(epoch).where(ts.notna(), other=np.nan)

    if epoch.isna().all():
        _log("Timestamps not parseable; assigning time_bucket=0 for all.")
        df["time_bucket"] = 0
        return df

    min_epoch = int(epoch.dropna().min())
    epoch = epoch.fillna(min_epoch)

    df["time_bucket"] = (epoch.astype("int64") // bucket_size) * bucket_size
    return df


def compute_event_features_doh(df: pd.DataFrame, config: Optional[DoHEventFeatureConfig] = None) -> pd.DataFrame:
    if config is None:
        config = DoHEventFeatureConfig()

    if config.prob_col not in df.columns:
        raise ValueError(f"Probability column '{config.prob_col}' not found.")

    df = df.copy()

    # Ensure endpoint cols exist
    if "client_ip" not in df.columns:
        df["client_ip"] = df.get("src_ip", "unknown")
    if "server_ip" not in df.columns:
        df["server_ip"] = df.get("dst_ip", "unknown")

    df["client_ip"] = df["client_ip"].fillna("unknown").astype(str)
    df["server_ip"] = df["server_ip"].fillna("unknown").astype(str)

    df = _add_time_bucket(df, config.bucket_size)

    df["is_high"] = df[config.prob_col].astype(float) >= float(config.high_prob_threshold)
    df["doh_key"] = df["client_ip"] + "|" + df["server_ip"]

    group_cols = ["time_bucket", "client_ip", "server_ip", "doh_key"]
    grouped = df.groupby(group_cols, as_index=False)

    events = grouped.agg(
        count=("is_high", "size"),
        high_count=("is_high", "sum"),
        mean_p=(config.prob_col, "mean"),
        max_p=(config.prob_col, "max"),
    )

    events["high_frac"] = np.where(events["count"] > 0, events["high_count"] / events["count"], 0.0)
    return events
