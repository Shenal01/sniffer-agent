#include "mysql_client.h"
#include <iostream>
#include <fmt/core.h>

namespace storage {

MySqlClient::MySqlClient() : conn_(nullptr) {}

MySqlClient::~MySqlClient() {
    disconnect();
}

bool MySqlClient::connect(const std::string& host, const std::string& user, const std::string& pass, const std::string& db, int port) {
    conn_ = mysql_init(nullptr);
    if (!conn_) {
        fmt::print(stderr, "mysql_init() failed\n");
        return false;
    }

    if (!mysql_real_connect(conn_, host.c_str(), user.c_str(), pass.c_str(), db.c_str(), port, nullptr, 0)) {
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

bool MySqlClient::execute(const std::string& query) {
    if (mysql_query(conn_, query.c_str())) {
        fmt::print(stderr, "mysql_query() failed: {}\n", mysql_error(conn_));
        return false;
    }
    return true;
}

bool MySqlClient::begin_transaction() {
    return execute("START TRANSACTION");
}

bool MySqlClient::commit() {
    return execute("COMMIT");
}

bool MySqlClient::rollback() {
    return execute("ROLLBACK");
}

std::string MySqlClient::escape(const std::string& str) {
    if (!conn_) return str;
    std::vector<char> escaped(str.length() * 2 + 1);
    mysql_real_escape_string(conn_, escaped.data(), str.c_str(), (unsigned long)str.length());
    return std::string(escaped.data());
}

} // namespace storage
