#pragma once

#include <mysql.h>
#include <string>
#include <vector>


namespace storage {

class MySqlClient {
public:
  MySqlClient();
  ~MySqlClient();

  bool connect(const std::string &host, const std::string &user,
               const std::string &pass, const std::string &db, int port = 3306);
  void disconnect();

  bool execute(const std::string &query);

  // Auto-reconnect: returns true if connection is alive (reconnects if needed)
  bool ping();

  // For batch inserts
  bool begin_transaction();
  bool commit();
  bool rollback();

  std::string escape(const std::string &str);
  std::string last_error() const;

private:
  MYSQL *conn_;
  // Store credentials for auto-reconnect
  std::string host_, user_, pass_, db_;
  int port_;
};

} // namespace storage
