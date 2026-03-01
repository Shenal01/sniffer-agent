import json
import csv
import re
import time
import logging
import argparse
from typing import Optional, Iterable

from scapy.all import sniff, DNS, DNSQR, IP, IPv6

# -----------------------------
# Normalization (Matches sniffer.py)
# -----------------------------
def normalize_domain_text(domain: str) -> str:
    """Lowercase + strip + remove URL/path if accidentally present."""
    domain = str(domain).strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0]
    return domain

def strip_trailing_dot(qname: str) -> str:
    return qname[:-1] if qname.endswith(".") else qname

def to_bytes_safe_qname(qname) -> str:
    if isinstance(qname, bytes):
        try:
            return qname.decode("utf-8", errors="ignore")
        except Exception:
            return str(qname)
    return str(qname)

def maybe_reduce_domain(qname: str) -> str:
    """Reduces subdomains to the base domain (e.g., a.b.com -> b.com)."""
    parts = [p for p in qname.split(".") if p]
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return qname

def is_reverse_lookup(qname: str) -> bool:
    q = qname.lower()
    return q.endswith(".in-addr.arpa") or q.endswith(".ip6.arpa")

def is_local_suffix(qname: str, suffixes: Iterable[str]) -> bool:
    q = qname.lower()
    return any(q.endswith(s.lower()) for s in suffixes)

# -----------------------------
# Simple Sniffer
# -----------------------------
class FeatureSniffer:
    def __init__(self, interface: Optional[str] = None, output_file: Optional[str] = None):
        self.interface = interface
        self.output_file = output_file
        self.log = logging.getLogger("feature_sniffer")
        self.local_suffixes = [".local", ".lan", ".home", ".internal", ".corp"]

        if self.output_file:
            # Initialize CSV header if file doesn't exist
            try:
                with open(self.output_file, 'x', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["timestamp", "src_ip", "raw_qname", "normalized_feature"])
            except FileExistsError:
                pass

    def _handle_packet(self, pkt) -> None:
        if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
            return

        dns_layer = pkt[DNS]
        if getattr(dns_layer, "qr", 0) != 0:  # Only capture queries
            return

        # Extract Raw QNAME
        qname_raw = pkt[DNSQR].qname
        qname = strip_trailing_dot(to_bytes_safe_qname(qname_raw))
        
        # Filtering
        if is_reverse_lookup(qname) or is_local_suffix(qname, self.local_suffixes):
            return

        # Feature Extraction (Normalization)
        normalized_qname = normalize_domain_text(qname)
        if not normalized_qname:
            return
            
        feature = normalized_qname # This is the primary feature for the ML model

        # Source IP
        src_ip = "unknown"
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
        elif pkt.haslayer(IPv6):
            src_ip = pkt[IPv6].src

        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"[{ts}] {src_ip} -> {feature}")

        if self.output_file:
            with open(self.output_file, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([ts, src_ip, qname, feature])

    def start(self):
        self.log.info(f"Starting DNS feature capture on {self.interface or 'default interface'}...")
        sniff(
            iface=self.interface,
            filter="udp port 53",
            prn=self._handle_packet,
            store=0
        )

def main():
    parser = argparse.ArgumentParser(description="Lightweight DNS Feature Sniffer (V2)")
    parser.add_argument("--interface", help="Network interface to sniff on")
    parser.add_argument("--output", help="Optional CSV file to save captured features")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    
    sniffer = FeatureSniffer(interface=args.interface, output_file=args.output)
    try:
        sniffer.start()
    except KeyboardInterrupt:
        print("\nStopping sniffer...")

if __name__ == "__main__":
    main()
