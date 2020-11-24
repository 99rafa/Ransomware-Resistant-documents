package server.database;

import java.sql.Connection;

public class Repository {
    private final Connection connection;

    public Repository(Connection c) {
        this.connection = c;
    }

    public Connection getConnection() {
        return connection;
    }
}
