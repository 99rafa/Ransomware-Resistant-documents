package server.database;


import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class Connector {

    private static final String DB_URL = "jdbc:mysql://localhost:3306/ransomdb";

    public Connection connection;

    public Connector(String user, String password) throws SQLException {
        this.connection = DriverManager.getConnection(DB_URL, user, password);
        this.connection.setAutoCommit(false);
    }

    public Connection getConnection() {
        return connection;
    }
}
