#pragma once

#include <string>
#include <vector>
#include <mysql.h> 

namespace storage {

class MySqlClient {
public:
    MySqlClient();
    ~MySqlClient();

    bool connect(const std::string& host, const std::string& user, const std::string& pass, const std::string& db, int port = 3306);
    void disconnect();

    bool execute(const std::string& query);
    
    // For batch inserts
    bool begin_transaction();
    bool commit();
    bool rollback();

    std::string escape(const std::string& str);

private:
    MYSQL* conn_;
};

} // namespace storage
