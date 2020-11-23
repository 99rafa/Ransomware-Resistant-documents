package server.database;

import server.domain.file.File;
import server.domain.file.FileRepository;
import server.domain.fileVersion.FileVersion;
import server.domain.fileVersion.FileVersionRepository;
import server.domain.user.User;
import server.domain.user.UserRepository;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Date;

public class Connector {

    private static final String DB_URL = "jdbc:mysql://localhost:3306/ransomdb";
    private static final String USER = "mateus";
    private static final String PASSWORD = "pass";

    public Connection connection;

    public Connector() throws SQLException {
        this.connection = DriverManager.getConnection(DB_URL, USER, PASSWORD);
        this.connection.setAutoCommit(false);
    }

    public static void main(String[] args) throws SQLException, ClassNotFoundException {
        Connector c = new Connector();

        /*String pass = "password";
        UserRepository userRepository = new UserRepository(c.connection);
        FileRepository fileRepository = new FileRepository(c.connection);
        FileVersionRepository fileVersionRepository = new FileVersionRepository(c.connection);
        User user = new User("Afonso",pass.getBytes());
        File file = new File("123","Afonso","ola.txt","1");
        FileVersion v1 = new FileVersion("1","123","Afonso", new Date());
        FileVersion v2 = new FileVersion("2","123","Afonso", new Date());
        FileVersion v3 = new FileVersion("3","123","Afonso", new Date());


        user.saveInDatabase(c);
        file.saveInDatabase(c);
        v1.saveInDatabase(c);
        v2.saveInDatabase(c);
        v3.saveInDatabase(c);

        User u1 = userRepository.getUserByUsername("Afonso");
        File f1 = fileRepository.getFileByUID("123");
        FileVersion fileVersion1 = fileVersionRepository.getFileVersionByUID("2");

        System.out.println(u1);
        System.out.println(f1);
        System.out.println(fileVersion1);*/

    }

    public Connection getConnection() {
        return connection;
    }
}
