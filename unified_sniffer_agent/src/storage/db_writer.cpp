#include "db_writer.h"
#include "sql_templates.h"
#include <fmt/core.h>
#include <sstream>

namespace storage {

DbWriter::DbWriter() : running_(false) {}

DbWriter::~DbWriter() { stop(); }

void DbWriter::start(const std::string &host, const std::string &user,
                     const std::string &pass, const std::string &db) {
  if (running_)
    return;

  if (!client_.connect(host, user, pass, db)) {
    fmt::print(
        stderr,
        "DbWriter: Failed to connect to database. Storage is NOT running.\n");
    return;
  }

  fmt::print("DbWriter: Successfully connected to database.\n");
  running_ = true;
  thread_ = std::thread(&DbWriter::writer_thread, this);
}

void DbWriter::stop() {
  if (!running_)
    return;

  running_ = false;
  cv_.notify_all();
  if (thread_.joinable()) {
    thread_.join();
  }
  client_.disconnect();
}

void DbWriter::queue_dns(const DnsRecord &record) {
  std::lock_guard<std::mutex> lock(mutex_);
  dns_queue_.push(record);
  if (dns_queue_.size() >= BATCH_SIZE) {
    cv_.notify_one();
  }
}

void DbWriter::queue_flow(const FlowRecord &record) {
  std::lock_guard<std::mutex> lock(mutex_);
  flow_queue_.push(record);
  if (flow_queue_.size() >= BATCH_SIZE) {
    cv_.notify_one();
  }
}

void DbWriter::queue_raw_sql(const std::string &sql) {
  std::lock_guard<std::mutex> lock(mutex_);
  raw_sql_queue_.push(sql);
  if (raw_sql_queue_.size() >= BATCH_SIZE) {
    cv_.notify_one();
  }
}

void DbWriter::writer_thread() {
  while (running_ || !dns_queue_.empty() || !flow_queue_.empty() ||
         !raw_sql_queue_.empty()) {
    std::vector<DnsRecord> dns_batch;
    std::vector<FlowRecord> flow_batch;
    std::vector<std::string> sql_batch;

    {
      std::unique_lock<std::mutex> lock(mutex_);
      cv_.wait_for(lock, std::chrono::seconds(5), [this] {
        return !running_ || dns_queue_.size() >= BATCH_SIZE ||
               flow_queue_.size() >= BATCH_SIZE ||
               raw_sql_queue_.size() >= BATCH_SIZE;
      });

      while (!dns_queue_.empty() && dns_batch.size() < BATCH_SIZE) {
        dns_batch.push_back(dns_queue_.front());
        dns_queue_.pop();
      }
      while (!flow_queue_.empty() && flow_batch.size() < BATCH_SIZE) {
        flow_batch.push_back(flow_queue_.front());
        flow_queue_.pop();
      }
      while (!raw_sql_queue_.empty() && sql_batch.size() < BATCH_SIZE) {
        sql_batch.push_back(raw_sql_queue_.front());
        raw_sql_queue_.pop();
      }
    }

    // Auto-reconnect check before writing
    if (!dns_batch.empty() || !flow_batch.empty() || !sql_batch.empty()) {
      if (!client_.ping()) {
        fmt::print(stderr,
                   "DbWriter: MySQL connection lost. Dropping batch.\n");
        continue;
      }
    }

    if (!dns_batch.empty()) {
      std::string query = INSERT_DNS_SQL;
      for (size_t i = 0; i < dns_batch.size(); ++i) {
        const auto &r = dns_batch[i];
        query += fmt::format(
            "('{}','{}',{},'{}',{},'{}','{}',{},'{}',{},'{}')", r.timestamp,
            r.src_ip, r.src_port, r.dst_ip, r.dst_port, r.traffic_type,
            client_.escape(r.domain_name), r.domain_name_len,
            client_.escape(r.sld), r.subdomain_len, client_.escape(r.tld));

        if (i < dns_batch.size() - 1)
          query += ",";
      }
      if (client_.execute(query)) {
        // fmt::print("DbWriter: Inserted DNS batch of {}\n", dns_batch.size());
      } else {
        fmt::print(stderr, "DbWriter: Failed to insert DNS batch: {}\n",
                   client_.last_error());
      }
    }

    if (!flow_batch.empty()) {
      std::string query = INSERT_FLOW_SQL;
      for (size_t i = 0; i < flow_batch.size(); ++i) {
        const auto &r = flow_batch[i];
        query += fmt::format(
            "('{}','{}','{}','{}',{},'{}',{},'{}',{},{},{},{},{},{})",
            r.timestamp, r.start_ts, r.end_ts, r.client_ip, r.client_port,
            r.server_ip, r.server_port, r.traffic_type, r.duration,
            r.flow_bytes_received, r.flow_bytes_sent, r.flow_received_rate,
            r.flow_sent_rate, r.packet_len_mean);

        if (i < flow_batch.size() - 1)
          query += ",";
      }
      if (client_.execute(query)) {
        // fmt::print("DbWriter: Inserted FLOW batch of {}\n",
        // flow_batch.size());
      } else {
        fmt::print(stderr, "DbWriter: Failed to insert FLOW batch: {}\n",
                   client_.last_error());
      }
    }

    if (!sql_batch.empty()) {
      for (const auto &sql : sql_batch) {
        if (!client_.execute(sql)) {
          fmt::print(
              stderr,
              "DbWriter: Failed to execute raw SQL (DNS Abuse Feature): {}\n",
              client_.last_error());
        }
      }
    }
  }
}

} // namespace storage
