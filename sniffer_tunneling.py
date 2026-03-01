# #!/usr/bin/env python3
# """
# live_sniffer.py (Unified DNS + DoH Sniffer) - Google Sheets output version

# What it does:
# - Captures Plain DNS queries (UDP/TCP 53) and appends each query as a row in Google Sheets
#   -> tab: plain_raw_query

# - Captures HTTPS/DoH-like flows (TCP 443) and appends each completed flow as a row in Google Sheets
#   -> tab: doh_raw_query

# Notes:
# - TCP 443 capture will include *all* HTTPS flows unless you restrict BPF to known DoH resolvers.
# - Flow stats are computed at FIN/RST (or on shutdown flush).
# """

# import argparse
# import logging
# import math
# import signal
# import sys
# import uuid
# from collections import Counter
# from datetime import datetime, timezone
# from pathlib import Path
# from typing import Any, Dict, List, Tuple

# import numpy as np
# from colorama import Fore, Style, init
# from scapy.all import sniff, DNS, DNSQR, IP, UDP, TCP  # type: ignore
# from scapy.layers.inet6 import IPv6  # type: ignore

# # -----------------------------
# # Bootstrap imports
# # -----------------------------
# THIS_FILE = Path(__file__).resolve()
# PROJECT_ROOT = THIS_FILE.parents[2]  # Exfiltrap-v2.0-prototype1
# if str(PROJECT_ROOT) not in sys.path:
#     sys.path.insert(0, str(PROJECT_ROOT))

# # NEW: Sheets repo
# from dns_tunneling.storage.sheets_repo import SheetsRepo, TabNames  # type: ignore

# # -----------------------------
# # Sheets config
# # -----------------------------
# DEFAULT_SHEET_ID = "1qBLWgiLiQ54kE3KctVGXh5jm-2U7o7UR3W9XCkeZkK4"
# DEFAULT_SA_JSON = str((PROJECT_ROOT / "firebase" / "firebase-service-account.json").resolve())

# # -----------------------------
# # Setup
# # -----------------------------
# init(autoreset=True)
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
# logging.getLogger("scapy.loading").setLevel(logging.ERROR)

# VOWELS = set("aeiou")


# def now_utc() -> datetime:
#     return datetime.now(timezone.utc)


# def utc_ts_float() -> float:
#     return datetime.now(timezone.utc).timestamp()


# def time_bucket_iso(ts: datetime, window_seconds: int = 60) -> str:
#     ts_utc = ts.astimezone(timezone.utc)
#     floored = ts_utc.replace(
#         second=(ts_utc.second // window_seconds) * window_seconds,
#         microsecond=0,
#     )
#     return floored.isoformat()


# # ============================================================
# # Plain DNS helpers
# # ============================================================

# def shannon_entropy(s: str) -> float:
#     if not s:
#         return 0.0
#     total = len(s)
#     counts = Counter(s)
#     return -sum((c / total) * math.log2(c / total) for c in counts.values())


# def extract_domain_parts(qname: str):
#     qname = qname.rstrip(".")
#     labels = qname.split(".")

#     dns_domain_name = qname
#     dns_domain_name_length = len(qname)

#     if len(labels) >= 2:
#         dns_top_level_domain = labels[-1]
#         dns_second_level_domain = labels[-2]
#     else:
#         dns_top_level_domain = ""
#         dns_second_level_domain = ""

#     if len(labels) > 2:
#         subdomain = ".".join(labels[:-2])
#     elif len(labels) == 2:
#         subdomain = labels[0]
#     elif len(labels) == 1:
#         subdomain = labels[0]
#     else:
#         subdomain = ""

#     dns_subdomain_name_length = len(subdomain)

#     return (
#         dns_domain_name,
#         dns_top_level_domain,
#         dns_second_level_domain,
#         dns_domain_name_length,
#         dns_subdomain_name_length,
#     )


# def lexical_raw_features(qname: str) -> Dict[str, Any]:
#     """
#     Deprecated: The heavy lexical features (numerical_percentage, entropy, etc.)
#     are now calculated in live_preprocess_lexical.py and live_preprocess_behavioural.py.
#     """
#     return {}


# def decode_qname(dns) -> str:
#     raw = dns.qd.qname
#     if isinstance(raw, (bytes, bytearray)):
#         return raw.decode("ascii", "ignore").rstrip(".")
#     return str(raw).rstrip(".")


# def sanitize_for_print(name: str) -> str:
#     safe = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in name)
#     return safe[:80] + ("…" if len(safe) > 80 else "")


# # ============================================================
# # DoH/HTTPS flow tracker (TCP 443)
# # ============================================================

# FlowKey = Tuple[str, int, str, int]  # (client_ip, client_port, server_ip, server_port=443)


# class DoHFlowTracker:
#     """
#     Tracks TCP 443 flows and emits a doc with the 29 flow features when FIN/RST is seen.
#     """

#     def __init__(self):
#         self.flows: Dict[FlowKey, Dict[str, Any]] = {}
#         self.flow_counter = 0

#     def _stats_packet_lengths(self, pkt_sizes: List[int]):
#         if not pkt_sizes:
#             return (0.0,) * 8
#         arr = np.array(pkt_sizes, dtype=float)
#         mean = float(arr.mean())
#         std = float(arr.std(ddof=0))
#         var = float(arr.var(ddof=0))
#         median = float(np.median(arr))
#         mode = float(max(Counter(pkt_sizes).items(), key=lambda kv: kv[1])[0])
#         skew_med = mean - median
#         skew_mode = mean - mode
#         cov = std / mean if mean > 0 else 0.0
#         return (var, std, mean, median, mode, skew_med, skew_mode, cov)

#     def _stats_times(self, values: List[float]):
#         if not values:
#             return (0.0,) * 8
#         arr = np.array(values, dtype=float)
#         mean = float(arr.mean())
#         std = float(arr.std(ddof=0))
#         var = float(arr.var(ddof=0))
#         median = float(np.median(arr))
#         mode = float(max(Counter(values).items(), key=lambda kv: kv[1])[0])
#         skew_med = mean - median
#         skew_mode = mean - mode
#         cov = std / mean if mean > 0 else 0.0
#         return (var, std, mean, median, mode, skew_med, skew_mode, cov)

#     def handle_packet(self, pkt):
#         if TCP not in pkt:
#             return None  # no output

#         tcp = pkt[TCP]
#         ts = utc_ts_float()

#         if IP in pkt:
#             src_ip = pkt[IP].src
#             dst_ip = pkt[IP].dst
#         elif IPv6 in pkt:
#             src_ip = pkt[IPv6].src
#             dst_ip = pkt[IPv6].dst
#         else:
#             return None

#         sport = int(tcp.sport)
#         dport = int(tcp.dport)

#         if sport != 443 and dport != 443:
#             return None

#         # Role detection
#         if dport == 443:
#             client_ip, client_port = src_ip, sport
#             server_ip, server_port = dst_ip, 443
#             direction = "cs"
#         else:
#             client_ip, client_port = dst_ip, dport
#             server_ip, server_port = src_ip, 443
#             direction = "sc"

#         key: FlowKey = (client_ip, client_port, server_ip, server_port)

#         if key not in self.flows:
#             self.flow_counter += 1
#             self.flows[key] = {
#                 "flow_id": self.flow_counter,
#                 "bytes_sent": 0,
#                 "bytes_recv": 0,
#                 "pkt_sizes": [],
#                 "pkt_times": [],
#                 "iat": [],
#                 "resp_times": [],
#                 "last_ts": None,
#                 "last_cs_ts": None,
#             }

#         flow = self.flows[key]
#         pkt_len = int(len(pkt))

#         flow["pkt_sizes"].append(pkt_len)
#         flow["pkt_times"].append(ts)

#         # IAT
#         if flow["last_ts"] is not None:
#             dt = ts - flow["last_ts"]
#             if dt >= 0:
#                 flow["iat"].append(dt)
#         flow["last_ts"] = ts

#         # Bytes and response times
#         if direction == "cs":
#             flow["bytes_sent"] += pkt_len
#             flow["last_cs_ts"] = ts
#         else:
#             flow["bytes_recv"] += pkt_len
#             if flow["last_cs_ts"] is not None:
#                 rt = ts - flow["last_cs_ts"]
#                 if rt >= 0:
#                     flow["resp_times"].append(rt)

#         # Finalize on FIN/RST
#         flags = int(tcp.flags)
#         if flags & 0x01 or flags & 0x04:  # FIN or RST
#             return self.finalize_flow(key)

#         return None

#     def finalize_flow(self, key: FlowKey):
#         flow = self.flows.pop(key, None)
#         if flow is None:
#             return None

#         pkt_times: List[float] = flow["pkt_times"]
#         if not pkt_times:
#             return None

#         start_ts = min(pkt_times)
#         end_ts = max(pkt_times)
#         duration = max(end_ts - start_ts, 0.0)

#         bytes_sent = int(flow["bytes_sent"])
#         bytes_recv = int(flow["bytes_recv"])
#         sent_rate = bytes_sent / duration if duration > 0 else 0.0
#         recv_rate = bytes_recv / duration if duration > 0 else 0.0

#         (pl_var, pl_std, pl_mean, pl_med, pl_mode, pl_sk_med, pl_sk_mode, pl_cov) = self._stats_packet_lengths(flow["pkt_sizes"])
#         (pt_var, pt_std, pt_mean, pt_med, pt_mode, pt_sk_med, pt_sk_mode, pt_cov) = self._stats_times(flow["iat"])
#         (rt_var, rt_std, rt_mean, rt_med, rt_mode, rt_sk_med, rt_sk_mode, rt_cov) = self._stats_times(flow["resp_times"])

#         client_ip, client_port, server_ip, server_port = key

#         return {
#             "flow_id": flow["flow_id"],
#             "client_ip": client_ip,
#             "client_port": int(client_port),
#             "server_ip": server_ip,
#             "server_port": int(server_port),
#             "start_ts": float(start_ts),
#             "end_ts": float(end_ts),

#             # 29 features (same names as your old DoH sniffer)
#             "Duration": float(duration),
#             "FlowBytesSent": int(bytes_sent),
#             "FlowSentRate": float(sent_rate),
#             "FlowBytesReceived": int(bytes_recv),
#             "FlowReceivedRate": float(recv_rate),

#             "PacketLengthVariance": float(pl_var),
#             "PacketLengthStandardDeviation": float(pl_std),
#             "PacketLengthMean": float(pl_mean),
#             "PacketLengthMedian": float(pl_med),
#             "PacketLengthMode": float(pl_mode),
#             "PacketLengthSkewFromMedian": float(pl_sk_med),
#             "PacketLengthSkewFromMode": float(pl_sk_mode),
#             "PacketLengthCoefficientofVariation": float(pl_cov),

#             "PacketTimeVariance": float(pt_var),
#             "PacketTimeStandardDeviation": float(pt_std),
#             "PacketTimeMean": float(pt_mean),
#             "PacketTimeMedian": float(pt_med),
#             "PacketTimeMode": float(pt_mode),
#             "PacketTimeSkewFromMedian": float(pt_sk_med),
#             "PacketTimeSkewFromMode": float(pt_sk_mode),
#             "PacketTimeCoefficientofVariation": float(pt_cov),

#             "ResponseTimeTimeVariance": float(rt_var),
#             "ResponseTimeTimeStandardDeviation": float(rt_std),
#             "ResponseTimeTimeMean": float(rt_mean),
#             "ResponseTimeTimeMedian": float(rt_med),
#             "ResponseTimeTimeMode": float(rt_mode),
#             "ResponseTimeTimeSkewFromMedian": float(rt_sk_med),
#             "ResponseTimeTimeSkewFromMode": float(rt_sk_mode),
#             "ResponseTimeTimeCoefficientofVariation": float(rt_cov),
#         }

#     def flush_all(self):
#         out = []
#         for k in list(self.flows.keys()):
#             doc = self.finalize_flow(k)
#             if doc is not None:
#                 out.append(doc)
#         return out


# # ============================================================
# # Unified Sniffer
# # ============================================================

# class UnifiedSniffer:
#     def __init__(self, sheet_id: str, sa_json: str):
#         self.repo = SheetsRepo(
#             spreadsheet_id=sheet_id,
#             service_account_json_path=sa_json,
#             tabs=TabNames(plain_raw_query="plain_raw_query", doh_raw_query="doh_raw_query", events="events"),
#         )

#         self.plain_flow_id = 0
#         self.doh_tracker = DoHFlowTracker()

#     def handle_packet(self, pkt):
#         # 1) Try plain DNS query
#         if DNS in pkt and DNSQR in pkt:
#             dns = pkt[DNS]
#             if dns.qr == 0:  # query
#                 self._handle_plain_dns(pkt)
#                 return

#         # 2) Try DoH/HTTPS flow stats (TCP 443)
#         doh_doc = self.doh_tracker.handle_packet(pkt)
#         if doh_doc is not None:
#             self._write_doh_doc(doh_doc)

#     def _handle_plain_dns(self, pkt):
#         # Ports
#         if UDP in pkt:
#             sport = int(pkt[UDP].sport)
#             dport = int(pkt[UDP].dport)
#         elif TCP in pkt:
#             sport = int(pkt[TCP].sport)
#             dport = int(pkt[TCP].dport)
#         else:
#             return

#         if sport != 53 and dport != 53:
#             return

#         # IPs
#         if IP in pkt:
#             src_ip = pkt[IP].src
#             dst_ip = pkt[IP].dst
#         elif IPv6 in pkt:
#             src_ip = pkt[IPv6].src
#             dst_ip = pkt[IPv6].dst
#         else:
#             return

#         qname = decode_qname(pkt[DNS])

#         (
#             dns_domain_name,
#             dns_top_level_domain,
#             dns_second_level_domain,
#             dns_domain_name_length,
#             dns_subdomain_name_length,
#         ) = extract_domain_parts(qname)

#         lex_raw = lexical_raw_features(dns_domain_name)

#         self.plain_flow_id += 1
#         now = now_utc()

#         doc_id = str(uuid.uuid4())
#         doc = {
#             "doc_id": doc_id,  # keep a stable id column like Firestore doc id
#             "traffic_type": "plain_dns",
#             "component": "dns_tunneling",

#             "flow_id": self.plain_flow_id,
#             "timestamp": now.isoformat(),
#             "time_bucket": time_bucket_iso(now, window_seconds=60),

#             "src_ip": src_ip,
#             "src_port": sport,
#             "dst_ip": dst_ip,
#             "dst_port": dport,

#             "dns_domain_name": dns_domain_name,
#             "dns_top_level_domain": dns_top_level_domain,
#             "dns_second_level_domain": dns_second_level_domain,
#             "dns_domain_name_length": int(dns_domain_name_length),
#             "dns_subdomain_name_length": int(dns_subdomain_name_length),

#             "lexical_raw": lex_raw,

#             "features": {
#                 "lexical": {"done": False},
#                 "behavioural": {"done": False},
#             },
#             "predictions": {
#                 "lexical": None,
#                 "behavioural": None,
#                 "fused": None,
#             },
#             "pipeline_status": {
#                 "raw_ingested": True,
#                 "features_extracted": False,
#                 "classified_lexical": False,
#                 "classified_behavioural": False,
#                 "fusion_done": False,
#                 "event_aggregated": False,
#             },
#         }

#         try:
#             self.repo.append_document("plain_raw_query", doc)
#             print(
#                 f"{Fore.YELLOW}[PLAIN]{Style.RESET_ALL} "
#                 f"{src_ip}:{sport} → {dst_ip}:{dport}  "
#                 f"{Fore.MAGENTA}{sanitize_for_print(dns_domain_name)}{Style.RESET_ALL} "
#                 f"(doc_id={doc_id})"
#             )
#         except Exception as e:
#             print(f"{Fore.RED}[!] Sheets write failed (plain): {e}{Style.RESET_ALL}")

#     def _write_doh_doc(self, flow_doc: Dict[str, Any]):
#         now = now_utc()
#         doc_id = str(uuid.uuid4())

#         doc = {
#             "doc_id": doc_id,
#             "traffic_type": "doh_https_flow",
#             "component": "dns_tunneling_doh",

#             "flow_id": flow_doc["flow_id"],
#             "timestamp": now.isoformat(),
#             "time_bucket": time_bucket_iso(now, window_seconds=60),

#             # endpoints
#             "client_ip": flow_doc["client_ip"],
#             "client_port": flow_doc["client_port"],
#             "server_ip": flow_doc["server_ip"],
#             "server_port": flow_doc["server_port"],

#             # 29 flow features (input for DoH preprocessors)
#             "flow_features": {
#                 k: v
#                 for k, v in flow_doc.items()
#                 if k not in {"client_ip", "client_port", "server_ip", "server_port"}
#             },

#             # DoH pipeline feature namespaces (set as NOT done initially; preprocessors will fill these)
#             "features": {
#                 "behavioural_rf": {"done": False},
#                 "behavioural_lr": {"done": False},
#                 "behavioural_if": {"done": False},
#                 "behavioural_ae": {"done": False},
#             },

#             # DoH model outputs (classifiers + fusion will populate)
#             "predictions": {
#                 "rf": None,
#                 "lr": None,
#                 "if": None,
#                 "ae": None,
#                 "fused": None,
#             },

#             # pipeline flags for DoH stages
#             "pipeline_status": {
#                 "raw_ingested": True,

#                 "features_extracted": False,
#                 "features_extracted_rf": False,
#                 "features_extracted_lr": False,
#                 "features_extracted_if": False,
#                 "features_extracted_ae": False,

#                 "classified_rf": False,
#                 "classified_lr": False,
#                 "classified_if": False,
#                 "classified_ae": False,

#                 "fusion_done": False,
#                 "event_aggregated": False,
#             },
#         }

#         try:
#             self.repo.append_document("doh_raw_query", doc)
#             print(
#                 f"{Fore.CYAN}[DOH]{Style.RESET_ALL} "
#                 f"{flow_doc['client_ip']}:{flow_doc['client_port']} → {flow_doc['server_ip']}:{flow_doc['server_port']}  "
#                 f"Dur={flow_doc['Duration']:.3f}s (doc_id={doc_id})"
#             )
#         except Exception as e:
#             print(f"{Fore.RED}[!] Sheets write failed (doh): {e}{Style.RESET_ALL}")

#     def flush(self):
#         docs = self.doh_tracker.flush_all()
#         for d in docs:
#             self._write_doh_doc(d)


# def main():
#     parser = argparse.ArgumentParser(description="Unified sniffer for Plain DNS (53) + DoH/HTTPS flows (443) to Google Sheets.")
#     parser.add_argument("--iface", "-i", default=None, help="Interface name (e.g., Ethernet). Default: system default.")
#     parser.add_argument(
#         "--bpf",
#         default=None,
#         help=(
#             "Optional BPF filter override.\n"
#             "Default captures BOTH:\n"
#             "  (udp port 53 or tcp port 53) or tcp port 443\n"
#             "Tip: restrict 443 to DoH resolvers, e.g.\n"
#             "  tcp port 443 and (host 1.1.1.1 or host 8.8.8.8)"
#         ),
#     )
#     parser.add_argument("--sheet-id", default=DEFAULT_SHEET_ID, help="Google Spreadsheet ID")
#     parser.add_argument("--sa-json", default=DEFAULT_SA_JSON, help="Service account JSON path")
#     args = parser.parse_args()

#     bpf = args.bpf or "((udp port 53 or tcp port 53) or tcp port 443)"
#     sn = UnifiedSniffer(sheet_id=args.sheet_id, sa_json=args.sa_json)

#     print(f"{Fore.GREEN}[*] Unified Sniffer started (Sheets mode){Style.RESET_ALL}")
#     print(f"    Interface : {args.iface if args.iface else '(default)'}")
#     print(f"    BPF filter: {bpf}")
#     print(f"    Sheet ID  : {args.sheet_id}")
#     print(f"    Tabs      : plain_raw_query | doh_raw_query")
#     print()

#     def _handle_exit(sig, frame):
#         print(f"\n{Fore.YELLOW}[*] Shutting down... flushing active 443 flows{Style.RESET_ALL}")
#         try:
#             sn.flush()
#         finally:
#             sys.exit(0)

#     signal.signal(signal.SIGINT, _handle_exit)
#     signal.signal(signal.SIGTERM, _handle_exit)

#     sniff(
#         iface=args.iface,
#         filter=bpf,
#         store=False,
#         prn=sn.handle_packet,
#     )


# if __name__ == "__main__":
#     main()

#!/usr/bin/env python3
"""
live_sniffer.py (Unified DNS + DoH Sniffer) - Google Sheets output version

What it does:
- Captures Plain DNS queries (UDP/TCP 53) and appends each query as a row in Google Sheets
  -> tab: plain_raw_query

- Captures HTTPS/DoH-like flows (TCP 443) and appends each completed flow as a row in Google Sheets
  -> tab: doh_raw_query

Notes:
- TCP 443 capture will include *all* HTTPS flows unless you restrict BPF to known DoH resolvers.
- Flow stats are computed at FIN/RST (or on shutdown flush).

UPDATED (Jan 2026):
- DoH is now IF + RF only (LR and AE removed).
- DoH sniffer no longer writes predictions containers (rf/if/lr/ae/fused = None),
  preventing unnecessary columns like predictions.rf, predictions.if, predictions.fused.
"""

import argparse
import logging
import math
import signal
import sys
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
from colorama import Fore, Style, init
from scapy.all import sniff, DNS, DNSQR, IP, UDP, TCP  # type: ignore
from scapy.layers.inet6 import IPv6  # type: ignore

# -----------------------------
# Bootstrap imports
# -----------------------------
THIS_FILE = Path(__file__).resolve()
PROJECT_ROOT = THIS_FILE.parents[2]  # Exfiltrap-v2.0-prototype1
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Sheets repo
from dns_tunneling.storage.sheets_repo import SheetsRepo, TabNames  # type: ignore

# -----------------------------
# Sheets config
# -----------------------------
DEFAULT_SHEET_ID = "1qBLWgiLiQ54kE3KctVGXh5jm-2U7o7UR3W9XCkeZkK4"
DEFAULT_SA_JSON = str((PROJECT_ROOT / "firebase" / "firebase-service-account.json").resolve())

# -----------------------------
# Setup
# -----------------------------
init(autoreset=True)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

VOWELS = set("aeiou")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def utc_ts_float() -> float:
    return datetime.now(timezone.utc).timestamp()


def time_bucket_iso(ts: datetime, window_seconds: int = 60) -> str:
    ts_utc = ts.astimezone(timezone.utc)
    floored = ts_utc.replace(
        second=(ts_utc.second // window_seconds) * window_seconds,
        microsecond=0,
    )
    return floored.isoformat()


# ============================================================
# Plain DNS helpers
# ============================================================

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    total = len(s)
    counts = Counter(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract_domain_parts(qname: str):
    qname = qname.rstrip(".")
    labels = qname.split(".")

    dns_domain_name = qname
    dns_domain_name_length = len(qname)

    if len(labels) >= 2:
        dns_top_level_domain = labels[-1]
        dns_second_level_domain = labels[-2]
    else:
        dns_top_level_domain = ""
        dns_second_level_domain = ""

    if len(labels) > 2:
        subdomain = ".".join(labels[:-2])
        dns_subdomain_name_length = len(subdomain)
    else:
        dns_subdomain_name_length = 0

    return (
        dns_domain_name,
        dns_top_level_domain,
        dns_second_level_domain,
        dns_domain_name_length,
        dns_subdomain_name_length,
    )


def lexical_raw_features(domain: str) -> Dict[str, Any]:
    """
    This sniffer stores only minimal lexical raw features.
    Heavy lexical features are calculated in live_preprocess_lexical.py and live_preprocess_behavioural.py.
    """
    return {}


def decode_qname(dns) -> str:
    raw = dns.qd.qname
    if isinstance(raw, (bytes, bytearray)):
        return raw.decode("ascii", "ignore").rstrip(".")
    return str(raw).rstrip(".")


def sanitize_for_print(name: str) -> str:
    safe = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in name)
    return safe[:80] + ("…" if len(safe) > 80 else "")


# ============================================================
# DoH/HTTPS flow tracker (TCP 443)
# ============================================================

FlowKey = Tuple[str, int, str, int]  # (client_ip, client_port, server_ip, server_port=443)


class DoHFlowTracker:
    """
    Tracks TCP 443 flows and emits a doc with the 29 flow features when FIN/RST is seen.
    """

    def __init__(self):
        self.flows: Dict[FlowKey, Dict[str, Any]] = {}
        self.flow_counter = 0

    def _stats_packet_lengths(self, pkt_sizes: List[int]):
        if not pkt_sizes:
            return (0.0,) * 8
        arr = np.array(pkt_sizes, dtype=float)
        mean = float(arr.mean())
        std = float(arr.std(ddof=0))
        var = float(arr.var(ddof=0))
        median = float(np.median(arr))
        mode = float(max(Counter(pkt_sizes).items(), key=lambda kv: kv[1])[0])
        skew_med = mean - median
        skew_mode = mean - mode
        cov = std / mean if mean > 0 else 0.0
        return (var, std, mean, median, mode, skew_med, skew_mode, cov)

    def _stats_times(self, values: List[float]):
        if not values:
            return (0.0,) * 8
        arr = np.array(values, dtype=float)
        mean = float(arr.mean())
        std = float(arr.std(ddof=0))
        var = float(arr.var(ddof=0))
        median = float(np.median(arr))
        mode = float(max(Counter(values).items(), key=lambda kv: kv[1])[0])
        skew_med = mean - median
        skew_mode = mean - mode
        cov = std / mean if mean > 0 else 0.0
        return (var, std, mean, median, mode, skew_med, skew_mode, cov)

    def handle_packet(self, pkt):
        if TCP not in pkt:
            return None  # no output

        tcp = pkt[TCP]
        ts = utc_ts_float()

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            return None

        sport = int(tcp.sport)
        dport = int(tcp.dport)

        if sport != 443 and dport != 443:
            return None

        # Role detection
        if dport == 443:
            client_ip, client_port = src_ip, sport
            server_ip, server_port = dst_ip, 443
            direction = "cs"
        else:
            client_ip, client_port = dst_ip, dport
            server_ip, server_port = src_ip, 443
            direction = "sc"

        key: FlowKey = (client_ip, client_port, server_ip, server_port)

        if key not in self.flows:
            self.flow_counter += 1
            self.flows[key] = {
                "flow_id": self.flow_counter,
                "bytes_sent": 0,
                "bytes_recv": 0,
                "pkt_sizes": [],
                "pkt_times": [],
                "iat": [],
                "resp_times": [],
                "last_ts": None,
                "last_cs_ts": None,
            }

        flow = self.flows[key]
        pkt_len = int(len(pkt))

        flow["pkt_sizes"].append(pkt_len)
        flow["pkt_times"].append(ts)

        # IAT
        if flow["last_ts"] is not None:
            dt = ts - flow["last_ts"]
            if dt >= 0:
                flow["iat"].append(dt)
        flow["last_ts"] = ts

        # Bytes and response times
        if direction == "cs":
            flow["bytes_sent"] += pkt_len
            flow["last_cs_ts"] = ts
        else:
            flow["bytes_recv"] += pkt_len
            if flow["last_cs_ts"] is not None:
                rt = ts - flow["last_cs_ts"]
                if rt >= 0:
                    flow["resp_times"].append(rt)

        # Finalize on FIN/RST
        flags = int(tcp.flags)
        if flags & 0x01 or flags & 0x04:  # FIN or RST
            return self.finalize_flow(key)

        return None

    def finalize_flow(self, key: FlowKey):
        flow = self.flows.pop(key, None)
        if flow is None:
            return None

        pkt_times: List[float] = flow["pkt_times"]
        if not pkt_times:
            return None

        start_ts = min(pkt_times)
        end_ts = max(pkt_times)
        duration = max(end_ts - start_ts, 0.0)

        bytes_sent = int(flow["bytes_sent"])
        bytes_recv = int(flow["bytes_recv"])
        sent_rate = bytes_sent / duration if duration > 0 else 0.0
        recv_rate = bytes_recv / duration if duration > 0 else 0.0

        (pl_var, pl_std, pl_mean, pl_med, pl_mode, pl_sk_med, pl_sk_mode, pl_cov) = self._stats_packet_lengths(flow["pkt_sizes"])
        (pt_var, pt_std, pt_mean, pt_med, pt_mode, pt_sk_med, pt_sk_mode, pt_cov) = self._stats_times(flow["iat"])
        (rt_var, rt_std, rt_mean, rt_med, rt_mode, rt_sk_med, rt_sk_mode, rt_cov) = self._stats_times(flow["resp_times"])

        client_ip, client_port, server_ip, server_port = key

        return {
            "flow_id": flow["flow_id"],
            "client_ip": client_ip,
            "client_port": int(client_port),
            "server_ip": server_ip,
            "server_port": int(server_port),
            "start_ts": float(start_ts),
            "end_ts": float(end_ts),

            # 29 features
            "Duration": float(duration),
            "FlowBytesSent": int(bytes_sent),
            "FlowSentRate": float(sent_rate),
            "FlowBytesReceived": int(bytes_recv),
            "FlowReceivedRate": float(recv_rate),

            "PacketLengthVariance": float(pl_var),
            "PacketLengthStandardDeviation": float(pl_std),
            "PacketLengthMean": float(pl_mean),
            "PacketLengthMedian": float(pl_med),
            "PacketLengthMode": float(pl_mode),
            "PacketLengthSkewFromMedian": float(pl_sk_med),
            "PacketLengthSkewFromMode": float(pl_sk_mode),
            "PacketLengthCoefficientofVariation": float(pl_cov),

            "PacketTimeVariance": float(pt_var),
            "PacketTimeStandardDeviation": float(pt_std),
            "PacketTimeMean": float(pt_mean),
            "PacketTimeMedian": float(pt_med),
            "PacketTimeMode": float(pt_mode),
            "PacketTimeSkewFromMedian": float(pt_sk_med),
            "PacketTimeSkewFromMode": float(pt_sk_mode),
            "PacketTimeCoefficientofVariation": float(pt_cov),

            "ResponseTimeTimeVariance": float(rt_var),
            "ResponseTimeTimeStandardDeviation": float(rt_std),
            "ResponseTimeTimeMean": float(rt_mean),
            "ResponseTimeTimeMedian": float(rt_med),
            "ResponseTimeTimeMode": float(rt_mode),
            "ResponseTimeTimeSkewFromMedian": float(rt_sk_med),
            "ResponseTimeTimeSkewFromMode": float(rt_sk_mode),
            "ResponseTimeTimeCoefficientofVariation": float(rt_cov),
        }

    def flush_all(self):
        out = []
        for k in list(self.flows.keys()):
            doc = self.finalize_flow(k)
            if doc is not None:
                out.append(doc)
        return out


# ============================================================
# Unified Sniffer
# ============================================================

class UnifiedSniffer:
    def __init__(self, sheet_id: str, sa_json: str):
        self.repo = SheetsRepo(
            spreadsheet_id=sheet_id,
            service_account_json_path=sa_json,
            tabs=TabNames(plain_raw_query="plain_raw_query", doh_raw_query="doh_raw_query", events="events"),
        )

        self.plain_flow_id = 0
        self.doh_tracker = DoHFlowTracker()

    def handle_packet(self, pkt):
        # 1) Try plain DNS query
        if DNS in pkt and DNSQR in pkt:
            dns = pkt[DNS]
            if dns.qr == 0:  # query
                self._handle_plain_dns(pkt)
                return

        # 2) Try DoH/HTTPS flow stats (TCP 443)
        doh_doc = self.doh_tracker.handle_packet(pkt)
        if doh_doc is not None:
            self._write_doh_doc(doh_doc)

    def _handle_plain_dns(self, pkt):
        # Ports
        if UDP in pkt:
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
        elif TCP in pkt:
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
        else:
            return

        if sport != 53 and dport != 53:
            return

        # IPs
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            return

        qname = decode_qname(pkt[DNS])

        (
            dns_domain_name,
            dns_top_level_domain,
            dns_second_level_domain,
            dns_domain_name_length,
            dns_subdomain_name_length,
        ) = extract_domain_parts(qname)

        lex_raw = lexical_raw_features(dns_domain_name)

        self.plain_flow_id += 1
        now = now_utc()

        doc_id = str(uuid.uuid4())
        doc = {
            "doc_id": doc_id,
            "traffic_type": "plain_dns",
            "component": "dns_tunneling",

            "flow_id": self.plain_flow_id,
            "timestamp": now.isoformat(),
            "time_bucket": time_bucket_iso(now, window_seconds=60),

            "src_ip": src_ip,
            "src_port": sport,
            "dst_ip": dst_ip,
            "dst_port": dport,

            "dns_domain_name": dns_domain_name,
            "dns_top_level_domain": dns_top_level_domain,
            "dns_second_level_domain": dns_second_level_domain,
            "dns_domain_name_length": int(dns_domain_name_length),
            "dns_subdomain_name_length": int(dns_subdomain_name_length),

            "lexical_raw": lex_raw,

            "features": {
                "lexical": {"done": False},
                "behavioural": {"done": False},
            },
            # (unchanged) plain pipeline placeholders
            "predictions": {
                "lexical": None,
                "behavioural": None,
                "fused": None,
            },
            "pipeline_status": {
                "raw_ingested": True,
                "features_extracted": False,
                "classified_lexical": False,
                "classified_behavioural": False,
                "fusion_done": False,
                "event_aggregated": False,
            },
        }

        try:
            self.repo.append_document("plain_raw_query", doc)
            print(
                f"{Fore.YELLOW}[PLAIN]{Style.RESET_ALL} "
                f"{src_ip}:{sport} → {dst_ip}:{dport}  "
                f"{Fore.MAGENTA}{sanitize_for_print(dns_domain_name)}{Style.RESET_ALL} "
                f"(doc_id={doc_id})"
            )
        except Exception as e:
            print(f"{Fore.RED}[!] Sheets write failed (plain): {e}{Style.RESET_ALL}")

    def _write_doh_doc(self, flow_doc: Dict[str, Any]):
        now = now_utc()
        doc_id = str(uuid.uuid4())

        doc = {
            "doc_id": doc_id,
            "traffic_type": "doh_https_flow",
            "component": "dns_tunneling_doh",

            "flow_id": flow_doc["flow_id"],
            "timestamp": now.isoformat(),
            "time_bucket": time_bucket_iso(now, window_seconds=60),

            # endpoints
            "client_ip": flow_doc["client_ip"],
            "client_port": flow_doc["client_port"],
            "server_ip": flow_doc["server_ip"],
            "server_port": flow_doc["server_port"],

            # 29 flow features (input for DoH preprocessors)
            "flow_features": {
                k: v
                for k, v in flow_doc.items()
                if k not in {"client_ip", "client_port", "server_ip", "server_port"}
            },

            # ✅ DoH pipeline feature namespaces (IF + RF only)
            "features": {
                "behavioural_rf": {"done": False},
                "behavioural_if": {"done": False},
            },

            # ✅ DoH model outputs:
            # Do NOT write container placeholders like predictions.rf=None
            # Classifiers will write leaf fields such as:
            #   predictions.rf.score, predictions.rf.label
            #   predictions.if.label, predictions.if.score (if you store score)
            # Fusion will write:
            #   predictions.fused.score, predictions.fused.label, ...
            "predictions": {},

            # ✅ pipeline flags for DoH stages (IF + RF only)
            "pipeline_status": {
                "raw_ingested": True,

                "features_extracted": False,
                "features_extracted_rf": False,
                "features_extracted_if": False,

                "classified_rf": False,
                "classified_if": False,

                "fusion_done": False,
                "event_aggregated": False,
            },
        }

        try:
            self.repo.append_document("doh_raw_query", doc)
            print(
                f"{Fore.CYAN}[DOH]{Style.RESET_ALL} "
                f"{flow_doc['client_ip']}:{flow_doc['client_port']} → {flow_doc['server_ip']}:{flow_doc['server_port']}  "
                f"Dur={flow_doc['Duration']:.3f}s (doc_id={doc_id})"
            )
        except Exception as e:
            print(f"{Fore.RED}[!] Sheets write failed (doh): {e}{Style.RESET_ALL}")

    def flush(self):
        docs = self.doh_tracker.flush_all()
        for d in docs:
            self._write_doh_doc(d)


def main():
    parser = argparse.ArgumentParser(description="Unified sniffer for Plain DNS (53) + DoH/HTTPS flows (443) to Google Sheets.")
    parser.add_argument("--iface", "-i", default=None, help="Interface name (e.g., Ethernet). Default: system default.")
    parser.add_argument(
        "--bpf",
        default=None,
        help=(
            "Optional BPF filter override.\n"
            "Default captures BOTH:\n"
            "  (udp port 53 or tcp port 53) or tcp port 443\n"
            "Tip: restrict 443 to DoH resolvers, e.g.\n"
            "  tcp port 443 and (host 1.1.1.1 or host 8.8.8.8)"
        ),
    )
    parser.add_argument("--sheet-id", default=DEFAULT_SHEET_ID, help="Google Spreadsheet ID")
    parser.add_argument("--sa-json", default=DEFAULT_SA_JSON, help="Service account JSON path")
    args = parser.parse_args()

    bpf = args.bpf or "((udp port 53 or tcp port 53) or tcp port 443)"
    sn = UnifiedSniffer(sheet_id=args.sheet_id, sa_json=args.sa_json)

    print(f"{Fore.GREEN}[*] Unified Sniffer started (Sheets mode){Style.RESET_ALL}")
    print(f"    Interface : {args.iface if args.iface else '(default)'}")
    print(f"    BPF filter: {bpf}")
    print(f"    Sheet ID  : {args.sheet_id}")
    print(f"    Tabs      : plain_raw_query | doh_raw_query")
    print()

    def _handle_exit(sig, frame):
        print(f"\n{Fore.YELLOW}[*] Shutting down. flushing active 443 flows{Style.RESET_ALL}")
        try:
            sn.flush()
        finally:
            sys.exit(0)

    signal.signal(signal.SIGINT, _handle_exit)
    signal.signal(signal.SIGTERM, _handle_exit)

    sniff(
        iface=args.iface,
        filter=bpf,
        store=False,
        prn=sn.handle_packet,
    )


if __name__ == "__main__":
    main()
