# Unified DNS Sniffer Architecture Theory (Reference Model)

> This document defines the architectural theory for designing a Unified DNS Sniffer and its MySQL database structure.
> It is intended as a long-term reference for implementation.

Feature alignment is based on the documented sniffer specifications and component explanations.

---

# 1. Objective

The Unified DNS Sniffer must:

1. Capture all DNS-related traffic (Plain DNS + DoH).
2. Store all raw and base-derived features in centralized **ALL tables**.
3. Allow independent detection modules:
   - DNS Tunneling (Plain)
   - DNS Tunneling (DoH)
   - DNS DGA & C2
   - DNS Abuse
4. Prevent replication of raw traffic data.
5. Store ML outputs separately from captured traffic.

Core principle:

> Raw traffic is stored exactly once.  
> Detection modules reference raw traffic using stable identifiers.

---

# 2. Traffic Granularity Model

The system operates on two fundamental units:

| Unit Type | Description | Used By |
|------------|-------------|----------|
| Query | Single DNS request (UDP/TCP 53) | DGA, Plain DNS Tunneling |
| Flow | 5-tuple session (TCP/UDP session) | DoH Tunneling, DNS Abuse |

This separation is mandatory for clean relational design.

---

# 3. Base Traffic Tables (Source of Truth)

Two core tables must exist.

---

## 3.1 DNS All – Plain (Query-Level)

**One row per DNS query.**

Includes:
- Timestamp
- Source/Destination IP and ports
- Transport protocol
- Raw domain
- Normalized domain
- Structural domain fields
- Base lexical information

This table serves:

- DNS Tunneling (Plain)
- DNS DGA & C2
- DNS Abuse (port 53 flows)

### Key Properties

- Primary Key: `plain_id`
- Every query is inserted immediately.
- No aggregation happens here.
- No detection results stored here.

---

## 3.2 DNS All – DoH (Flow-Level)

**One row per completed TCP flow (typically 443).**

Includes:
- 5-tuple identification
- Flow start and end timestamps
- 29 statistical flow features
- Optional TLS/SNI metadata

Flow statistics correspond to DoH sniffer feature extraction .

### Key Properties

- Primary Key: `doh_id`
- Created when flow closes (FIN/RST/timeout).
- Represents a complete flow instance.
- No duplication across other tables.

---

# 4. Detection Modules and Relationships

Detection modules never duplicate raw traffic data.
They store only enrichment results.

---

## 4.1 DNS Tunneling – Plain

- Operates per query.
- Reads from `dns_all_plain`.
- Writes ML output to separate table keyed by `plain_id`.

Relationship: dns_all_plain (1) → dns_tunneling_plain (1)

---

## 4.2 DNS DGA & C2

- Operates per query.
- Reads from `dns_all_plain`.
- Writes ML output keyed by `plain_id`.

Relationship: dns_all_plain (1) → dns_dga_c2 (1)

---

## 4.3 DNS Tunneling – DoH

- Operates per flow.
- Reads from `dns_all_doh`.
- Writes ML output keyed by `doh_id`.

Relationship: dns_all_doh (1) → dns_tunneling_doh (1)

---

## 4.4 DNS Abuse (Flow-Based Aggregation)

DNS Abuse operates using **5-tuple aggregation**:
- (Source IP, Destination IP, Source Port, Destination Port, Protocol)

As defined in the flow-based architecture.

### Aggregation Rule

All packets sharing the same 5-tuple within a flow instance are bundled.

Abuse computes:

- Amplification factor
- Query/response ratio
- ANY/TXT ratios
- Flow duration
- Packet/byte rates
- IAT statistics
- DPI metrics

Feature list reference uses standard DPI metrics.

---

# 5. Unified Identifier Strategy

To prevent replication:

## 5.1 Flow Identifier

Each 5-tuple flow instance must have a stable `flow_id`.

This represents the bundled traffic set.

---

## 5.2 Linking Queries to Flows (Optional)

`dns_all_plain` may include: flow_id (nullable)

This allows: Many queries → One flow & One abuse record → One flow

Relationship model: dns_all_plain (many) → flow_id (one) & dns_abuse (one) → flow_id (one)

No duplication required.

---

# 6. Architectural Guarantees

## Guarantee 1 – Raw Traffic Stored Once
All DNS queries and flows are inserted into ALL tables first.

## Guarantee 2 – Detection Tables Store Only Enrichment
Detection tables contain:
- ML scores
- Labels
- Severity
- Model version
- Rule results

They do not store duplicate traffic fields.

## Guarantee 3 – Aggregation Never Removes Queries
DNS Abuse creates summary rows.
Individual query rows remain intact.

Therefore:
- DGA sees all queries.
- Plain tunneling sees all queries.
- DoH tunneling sees all flows.
- Abuse sees bundled flows.

No detection process loses data.

---

# 7. Unified Processing Flow

1. Packet captured.
2. If DNS query → insert into `dns_all_plain`.
3. If DoH flow completes → insert into `dns_all_doh`.
4. Abuse engine aggregates per 5-tuple flow → insert into `dns_abuse`.
5. ML modules read base tables and insert outputs into their respective detection tables.

---

# 8. Structural Overview
dns_all_plain -----> dns_dga_c2
|
|-----> dns_tunneling_plain
|
|-----> dns_abuse (if linked to plain flow)

dns_all_doh -----> dns_tunneling_doh
|
|-----> dns_abuse


---

# 9. Final Principle

The Unified DNS Sniffer must:

- Separate query-level and flow-level data.
- Store raw capture data exactly once.
- Use stable identifiers (`plain_id`, `doh_id`, `flow_id`).
- Allow detection modules to operate independently.
- Prevent traffic duplication across tables.

This ensures scalability, relational integrity, and correctness of all ML detection pipelines.
