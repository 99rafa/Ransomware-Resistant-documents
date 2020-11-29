package server.database;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
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

        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        try {
            assert ks != null;
            ks.load(new FileInputStream("src/assets/keyStores/clientStore.p12"), "vjZx~R::Vr=s7]bz#".toCharArray());
        } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
        }


    }

    public Connection getConnection() {
        return connection;
    }
}
