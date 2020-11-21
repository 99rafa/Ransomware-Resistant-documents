package server.database;

import server.domain.file.File;
import server.domain.fileVersion.FileVersion;
import server.domain.user.User;
import server.domain.user.UserRepository;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Date;

public class Connector {

    private static final String JDBC_DRIVER = "com.mysql.jdbc.Driver";
    private static final String DB_URL = "jdbc:mysql://localhost:3306/ransomdb";
    private static final String USER = "afonso";
    private static final String PASSWORD = "password";

    public Connection connection;

    public Connector() throws SQLException {
        this.connection = DriverManager.getConnection(DB_URL, USER, PASSWORD);
        this.connection.setAutoCommit(false);
    }

    public static void main(String[] args) throws SQLException, ClassNotFoundException {
        Connector c = new Connector();

        String pass = "password";
        UserRepository userRepository = new UserRepository(c.connection);
        User user = new User("Afonso",pass.getBytes());
        File file = new File("123","Afonso","ola.txt","1");
        FileVersion v1 = new FileVersion("1","123","Afonso","path1", new Date());
        FileVersion v2 = new FileVersion("2","123","Afonso","path2", new Date());
        FileVersion v3 = new FileVersion("3","123","Afonso","path3", new Date());


        user.saveInDatabase(c);
        file.saveInDatabase(c);
        v1.saveInDatabase(c);
        v2.saveInDatabase(c);
        v3.saveInDatabase(c);

        User u1 = userRepository.getUserByUsername("Afonso");
        System.out.println(u1.getUsername());
        System.out.println(Arrays.equals(u1.getPassHash(), pass.getBytes()));
        System.out.println(u1.getOwnedFiles());
        System.out.println(u1.getCreatedVersions());
        System.out.println(u1.getEditableFiles());
        System.out.println(u1.getReadableFiles());

    }

}
