package server.domain.user;


import server.database.Connector;
import server.database.DatabaseObject;

import java.io.ByteArrayInputStream;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


public class User implements DatabaseObject {

    //PK
    private String username;

    private byte[] passHash;

    private byte[] salt;

    private int iterations;

    private byte[] publicKey;


    //MTM
    private List<String> editableFiles = new ArrayList<>();
    //MTM
    private List<String> readableFiles = new ArrayList<>();
    //OTM
    private List<String> ownedFiles = new ArrayList<>();
    //OTM
    private List<String> createdVersions = new ArrayList<>();


    public User(String username, byte[] passHash, byte[] salt, int iterations, byte[] publicKey) {

        this.username = username;
        this.passHash = passHash;
        this.salt = salt;
        this.iterations = iterations;
        this.publicKey = publicKey;
    }

    public User() {

    }

    public List<String> getCreatedVersions() {
        return createdVersions;
    }

    public void setCreatedVersions(List<String> createdVersions) {
        this.createdVersions = createdVersions;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public byte[] getPassHash() {
        return passHash;
    }

    public void setPassHash(byte[] passHash) {
        this.passHash = passHash;
    }

    public List<String> getEditableFiles() {
        return editableFiles;
    }

    public void setEditableFiles(List<String> editableFiles) {
        this.editableFiles = editableFiles;
    }

    public List<String> getReadableFiles() {
        return readableFiles;
    }

    public void setReadableFiles(List<String> readableFiles) {
        this.readableFiles = readableFiles;
    }

    public byte[] getSalt() {
        return salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public int getIterations() {
        return iterations;
    }

    public void setIterations(int iterations) {
        this.iterations = iterations;
    }

    public List<String> getOwnedFiles() {
        return ownedFiles;
    }

    public void setOwnedFiles(List<String> ownedFiles) {
        this.ownedFiles = ownedFiles;
    }

    public void addEditableFile(String file) {
        this.editableFiles.add(file);
    }

    public void addReadableFile(String file) {
        this.readableFiles.add(file);
    }

    public void addOwnedFile(String file) {
        this.ownedFiles.add(file);
    }

    public byte[] getPublicKey() { return publicKey; }

    public void setPublicKey(byte[] publicKey) { this.publicKey = publicKey; }


    @Override
    public void saveInDatabase(Connector connector) {
        try {
            //Insert user
            String sql = "INSERT INTO Users VALUES (?,?,?,?,?)";

            PreparedStatement s = connector.connection.prepareStatement(sql);

            //Set parameters
            s.setString(1, this.username);
            s.setBinaryStream(2, new ByteArrayInputStream(this.passHash));
            s.setBinaryStream(3, new ByteArrayInputStream(this.salt));
            s.setInt(4, this.iterations);
            s.setBinaryStream(5, new ByteArrayInputStream(this.publicKey));


            //Commit transaction
            connector.connection.commit();
        } catch (SQLException e) {
            e.printStackTrace();
            //Rollback changes in case of failure
            try {
                connector.connection.rollback();
            } catch (SQLException ignored) {
            }
        }
    }

    @Override
    public String toString() {
        return "User{" +
                "username='" + username + '\'' +
                ", passHash=" + Arrays.toString(passHash) +
                ", publicKey=" + Arrays.toString(publicKey) +
                ", editableFiles=" + editableFiles +
                ", readableFiles=" + readableFiles +
                ", ownedFiles=" + ownedFiles +
                ", createdVersions=" + createdVersions +
                '}';
    }
}
