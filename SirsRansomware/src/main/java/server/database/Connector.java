package server.database;


import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class Connector {

    private static final String DB_URL = "jdbc:mysql://localhost:3306/ransomdb";
    private static final String USER = "afonso";
    private static final String PASSWORD = "password";


    public Connection connection;

    public Connector() throws SQLException {
        this.connection = DriverManager.getConnection(DB_URL, USER, PASSWORD);
        this.connection.setAutoCommit(false);
    }

    public Connection getConnection() {
        return connection;
    }
}
