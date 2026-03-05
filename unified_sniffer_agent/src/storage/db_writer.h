#pragma once

#include "common/types.h"
#include "mysql_client.h"
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <queue>
#include <thread>

namespace storage {

class DbWriter {
public:
  DbWriter();
  ~DbWriter();

  void start(const std::string &host, const std::string &user,
             const std::string &pass, const std::string &db);
  void stop();

  bool is_connected() const { return running_; }

  void queue_dns(const DnsRecord &record);
  void queue_flow(const FlowRecord &record);
  void queue_raw_sql(const std::string &sql);

private:
  void writer_thread();

  MySqlClient client_;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::queue<DnsRecord> dns_queue_;
  std::queue<FlowRecord> flow_queue_;
  std::queue<std::string> raw_sql_queue_;
  std::atomic<bool> running_;
  std::thread thread_;

  const size_t BATCH_SIZE = 100;
};

} // namespace storage
