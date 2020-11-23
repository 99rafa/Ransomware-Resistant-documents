package server.domain.user;


import server.database.Connector;
import server.database.DatabaseObject;

import java.io.ByteArrayInputStream;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.SQLIntegrityConstraintViolationException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


public class User implements DatabaseObject {

    //PK
    private String username;

    private byte[] passHash;

    //MTM
    private List<String> editableFiles = new ArrayList<>();
    //MTM
    private List<String> readableFiles = new ArrayList<>();
    //OTM
    private List<String> ownedFiles = new ArrayList<>();
    //OTM
    private List<String> createdVersions = new ArrayList<>();

    public User(String username, byte[] passHash) {
        this.username = username;
        this.passHash = passHash;
    }

    public User() {

    }

    public List<String> getCreatedVersions() {
        return createdVersions;
    }

    public void setCreatedVersions(List<String> createdVersions) {
        this.createdVersions = createdVersions;
    }

    public void setEditableFiles(List<String> editableFiles) {
        this.editableFiles = editableFiles;
    }

    public void setReadableFiles(List<String> readableFiles) {
        this.readableFiles = readableFiles;
    }

    public void setOwnedFiles(List<String> ownedFiles) {
        this.ownedFiles = ownedFiles;
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

    public List<String> getReadableFiles() {
        return readableFiles;
    }


    public List<String> getOwnedFiles() {
        return ownedFiles;
    }


    public void addEditableFile(String file){
        this.editableFiles.add(file);
    }
    public void addReadableFile(String file){
        this.readableFiles.add(file);
    }
    public void addOwnedFile(String file){
        this.ownedFiles.add(file);
    }

    @Override
    public void saveInDatabase(Connector connector) {
        try {
            //Insert user
            String sql = "INSERT INTO Users VALUES (?,?)";
            PreparedStatement s = connector.connection.prepareStatement(sql);

            //Set parameters
            s.setString(1,this.username);
            s.setBinaryStream(2,new ByteArrayInputStream(this.passHash));
            s.executeUpdate();

            //Commit transaction
            connector.connection.commit();
        }
        catch (SQLException e) {
            e.printStackTrace();
            //Rollback changes in case of failure
            try {
                connector.connection.rollback();
            } catch (SQLException ignored) { }
        }
    }

    @Override
    public String toString() {
        return "User{" +
                "username='" + username + '\'' +
                ", passHash=" + Arrays.toString(passHash) +
                ", editableFiles=" + editableFiles +
                ", readableFiles=" + readableFiles +
                ", ownedFiles=" + ownedFiles +
                ", createdVersions=" + createdVersions +
                '}';
    }
}
