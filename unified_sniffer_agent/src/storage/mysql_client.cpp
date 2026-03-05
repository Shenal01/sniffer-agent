#include "mysql_client.h"
#include <fmt/core.h>
#include <iostream>

namespace storage {

MySqlClient::MySqlClient() : conn_(nullptr), port_(3306) {}

MySqlClient::~MySqlClient() { disconnect(); }

bool MySqlClient::connect(const std::string &host, const std::string &user,
                          const std::string &pass, const std::string &db,
                          int port) {
  // Store credentials for auto-reconnect
  host_ = host;
  user_ = user;
  pass_ = pass;
  db_ = db;
  port_ = port;

  conn_ = mysql_init(nullptr);
  if (!conn_) {
    fmt::print(stderr, "mysql_init() failed\n");
    return false;
  }

  // Disable strict SSL verification for the Ubuntu Self-Signed CA
  bool ssl_verify = false;
  mysql_options(conn_, MYSQL_OPT_SSL_VERIFY_SERVER_CERT, &ssl_verify);

  // Enable auto-reconnect at the MySQL C API level
  bool reconnect_opt = true;
  mysql_options(conn_, MYSQL_OPT_RECONNECT, &reconnect_opt);

  if (!mysql_real_connect(conn_, host.c_str(), user.c_str(), pass.c_str(),
                          db.c_str(), port, nullptr, 0)) {
    fmt::print(stderr, "mysql_real_connect() failed: {}\n", mysql_error(conn_));
    mysql_close(conn_);
    conn_ = nullptr;
    return false;
  }

  return true;
}

void MySqlClient::disconnect() {
  if (conn_) {
    mysql_close(conn_);
    conn_ = nullptr;
  }
}

bool MySqlClient::execute(const std::string &query) {
  if (mysql_query(conn_, query.c_str())) {
    fmt::print(stderr, "mysql_query() failed: {}\n", mysql_error(conn_));
    return false;
  }
  return true;
}

bool MySqlClient::begin_transaction() { return execute("START TRANSACTION"); }

bool MySqlClient::commit() { return execute("COMMIT"); }

bool MySqlClient::rollback() { return execute("ROLLBACK"); }

std::string MySqlClient::escape(const std::string &str) {
  if (!conn_)
    return str;
  std::vector<char> escaped(str.length() * 2 + 1);
  mysql_real_escape_string(conn_, escaped.data(), str.c_str(),
                           (unsigned long)str.length());
  return std::string(escaped.data());
}

bool MySqlClient::ping() {
  if (!conn_)
    return false;
  if (mysql_ping(conn_) == 0)
    return true;

  // Connection lost — attempt full reconnect
  fmt::print(stderr, "MySqlClient: Connection lost ({}). Reconnecting...\n",
             mysql_error(conn_));
  disconnect();
  return connect(host_, user_, pass_, db_, port_);
}

std::string MySqlClient::last_error() const {
  if (!conn_)
    return "No connection";
  return std::string(mysql_error(conn_));
}

} // namespace storage
