# DNS Sniffer Features Storage

This document contains a comprehensive list of all features extracted and stored by the three different sniffer components in the `sniffer_agent` directory.

## 1. DNS Tunneling Sniffer (`sniffer_tunneling.py`)

### A. Plain DNS (`plain_raw_query` tab)
*   **doc_id**
*   **traffic_type** (Hardcoded: "plain_dns")
*   **component** (Hardcoded: "dns_tunneling")
*   **flow_id**
*   **timestamp**
*   **time_bucket**
*   **src_ip**
*   **src_port**
*   **dst_ip**
*   **dst_port**
*   **dns_domain_name**
*   **dns_top_level_domain**
*   **dns_second_level_domain**
*   **dns_domain_name_length**
*   **dns_subdomain_name_length**
*   **lexical_raw** (Empty dictionary)
*   **features**
*   **predictions**
*   **pipeline_status**

### B. DoH / HTTPS Flow (`doh_raw_query` tab)
*   **doc_id**
*   **traffic_type** (Hardcoded: "doh_https_flow")
*   **component** (Hardcoded: "dns_tunneling_doh")
*   **flow_id**
*   **timestamp**
*   **time_bucket**
*   **client_ip**
*   **client_port**
*   **server_ip**
*   **server_port**
*   **Duration**
*   **FlowBytesSent**
*   **FlowSentRate**
*   **FlowBytesReceived**
*   **FlowReceivedRate**
*   **PacketLengthVariance**
*   **PacketLengthStandardDeviation**
*   **PacketLengthMean**
*   **PacketLengthMedian**
*   **PacketLengthMode**
*   **PacketLengthSkewFromMedian**
*   **PacketLengthSkewFromMode**
*   **PacketLengthCoefficientofVariation**
*   **PacketTimeVariance**
*   **PacketTimeStandardDeviation**
*   **PacketTimeMean**
*   **PacketTimeMedian**
*   **PacketTimeMode**
*   **PacketTimeSkewFromMedian**
*   **PacketTimeSkewFromMode**
*   **PacketTimeCoefficientofVariation**
*   **ResponseTimeTimeVariance**
*   **ResponseTimeTimeStandardDeviation**
*   **ResponseTimeTimeMean**
*   **ResponseTimeTimeMedian**
*   **ResponseTimeTimeMode**
*   **ResponseTimeTimeSkewFromMedian**
*   **ResponseTimeTimeSkewFromMode**
*   **ResponseTimeTimeCoefficientofVariation**
*   **features**
*   **predictions**
*   **pipeline_status**

## 2. DGA & C2 Sniffer (`sniffer_dga&c2.py`)

*   **timestamp**
*   **src_ip**
*   **raw_qname**
*   **normalized_feature**

## 3. DNS Abuse Sniffer (`sniffer_dnsAbuse` Java Tool)

*   **protocol**
*   **src_ip**
*   **dst_ip**
*   **src_port**
*   **dst_port**
*   **protocol_number**
*   **dns_amplification_factor**
*   **query_response_ratio**
*   **dns_any_query_ratio**
*   **dns_txt_query_ratio**
*   **dns_response_inconsistency**
*   **dns_queries_per_second**
*   **port_53_traffic_ratio**
*   **flow_bytes_per_sec**
*   **flow_packets_per_sec**
*   **fwd_packets_per_sec**
*   **bwd_packets_per_sec**
*   **flow_duration**
*   **total_fwd_packets**
*   **total_bwd_packets**
*   **total_fwd_bytes**
*   **total_bwd_bytes**
*   **dns_total_queries**
*   **dns_total_responses**
*   **dns_response_bytes**
*   **flow_iat_mean**
*   **flow_iat_std**
*   **flow_iat_min**
*   **flow_iat_max**
*   **fwd_iat_mean**
*   **bwd_iat_mean**
*   **fwd_packet_length_mean**
*   **bwd_packet_length_mean**
*   **packet_size_std**
*   **flow_length_min**
*   **flow_length_max**
*   **response_time_variance**
*   **average_packet_size**
*   **large_packet_ratio**
*   **medium_packet_ratio**
*   **small_packet_ratio**
*   **sni_entropy**
*   **is_known_doh_server**
*   **encrypted_payload_size_variance**
*   **label**

---

## 4. ALL FEATURES (Combined List)

### Flow Identification & Metadata
*   `doc_id`
*   `traffic_type`
*   `component`
*   `flow_id`
*   `timestamp`
*   `time_bucket`
*   `protocol`
*   `protocol_number`

### Endpoints
*   `src_ip` / `client_ip`
*   `src_port` / `client_port`
*   `dst_ip` / `server_ip`
*   `dst_port` / `server_port`

### DNS Lexical
*   `raw_qname`
*   `normalized_feature`
*   `dns_domain_name`
*   `dns_top_level_domain`
*   `dns_second_level_domain`
*   `dns_domain_name_length`
*   `dns_subdomain_name_length`
*   `lexical_raw`

### Flow Duration & Rates
*   `Duration` / `flow_duration`
*   `FlowBytesSent` / `total_fwd_bytes`
*   `FlowBytesReceived` / `total_bwd_bytes`
*   `FlowSentRate` / `fwd_packets_per_sec` (or bytes rate depending on calculation)
*   `FlowReceivedRate` / `bwd_packets_per_sec`
*   `flow_bytes_per_sec`
*   `flow_packets_per_sec`
*   `total_fwd_packets`
*   `total_bwd_packets`

### Feature Variances & Packet Distributions
*   `PacketLengthVariance` / `packet_size_std` / `flow_length_std`
*   `PacketLengthStandardDeviation`
*   `PacketLengthMean` / `average_packet_size`
*   `PacketLengthMedian`
*   `PacketLengthMode`
*   `PacketLengthSkewFromMedian`
*   `PacketLengthSkewFromMode`
*   `PacketLengthCoefficientofVariation`
*   `fwd_packet_length_mean`
*   `bwd_packet_length_mean`
*   `flow_length_min`
*   `flow_length_max`
*   `large_packet_ratio`
*   `medium_packet_ratio`
*   `small_packet_ratio`

### Timing & Inter-Arrival Time (IAT)
*   `PacketTimeVariance`
*   `PacketTimeStandardDeviation`
*   `PacketTimeMean`
*   `PacketTimeMedian`
*   `PacketTimeMode`
*   `PacketTimeSkewFromMedian`
*   `PacketTimeSkewFromMode`
*   `PacketTimeCoefficientofVariation`
*   `flow_iat_mean`
*   `flow_iat_std`
*   `flow_iat_min`
*   `flow_iat_max`
*   `fwd_iat_mean`
*   `bwd_iat_mean`

### Response Time Statistics
*   `ResponseTimeTimeVariance` / `response_time_variance`
*   `ResponseTimeTimeStandardDeviation`
*   `ResponseTimeTimeMean`
*   `ResponseTimeTimeMedian`
*   `ResponseTimeTimeMode`
*   `ResponseTimeTimeSkewFromMedian`
*   `ResponseTimeTimeSkewFromMode`
*   `ResponseTimeTimeCoefficientofVariation`

### DNS Deep Packet Inspection (DPI)
*   `dns_amplification_factor`
*   `query_response_ratio`
*   `dns_any_query_ratio`
*   `dns_txt_query_ratio`
*   `dns_response_inconsistency`
*   `dns_queries_per_second`
*   `port_53_traffic_ratio`
*   `dns_total_queries`
*   `dns_total_responses`
*   `dns_response_bytes`

### Encrypted DNS / DoH Specific
*   `sni_entropy`
*   `is_known_doh_server`
*   `encrypted_payload_size_variance`

### ML & Pipeline Status Flags
*   `label`
*   `features`
*   `predictions`
*   `pipeline_status`
