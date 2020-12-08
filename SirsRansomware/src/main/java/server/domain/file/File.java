package server.domain.file;

import server.database.Connector;
import server.database.DatabaseObject;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class File implements DatabaseObject {

    //PK
    private String uid;

    private String owner;

    private String name;

    //OTM
    private List<String> versions = new ArrayList<>();

    private String partition;

    private byte[] ownerAESEncrypted;

    private byte[] iv;

    public File(String uid, String owner, String name, String partition, byte[] AESEncrypted, byte[] iv) {
        this.uid = uid;
        this.owner = owner;
        this.name = name;
        this.partition = partition;
        this.ownerAESEncrypted = AESEncrypted;
        this.iv = iv;
    }

    public File() {
    }

    public byte[] getIv() {
        return iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }


    public void setVersions(List<String> versions) {
        this.versions = versions;
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public String getUid() {
        return uid;
    }

    public void setUid(String uid) {
        this.uid = uid;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPartition() {
        return partition;
    }

    public void setPartition(String partition) {
        this.partition = partition;
    }



    @Override
    public void saveInDatabase(Connector connector) {
        try {
            //Prepared statement
            String sql = "INSERT INTO Files VALUES (?,?,?,?,?)";
            PreparedStatement s = connector.connection.prepareStatement(sql);

            //Set parameters
            s.setString(1, this.uid);
            s.setString(2, this.owner);
            s.setString(3, this.name);
            s.setString(4, this.partition);
            s.setBytes(5, this.iv);
            s.executeUpdate();

            sql = "INSERT INTO EditableFiles VALUES (?,?,?)";
            s = connector.connection.prepareStatement(sql);

            s.setString(1, this.owner);
            s.setString(2, this.uid);
            s.setBytes(3, this.ownerAESEncrypted);
            s.executeUpdate();

            sql = "INSERT INTO ReadableFiles VALUES (?,?,?)";
            s = connector.connection.prepareStatement(sql);

            s.setString(1, this.owner);
            s.setString(2, this.uid);
            s.setBytes(3, this.ownerAESEncrypted);
            s.executeUpdate();

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
        return "File{" +
                "uid='" + uid + '\'' +
                ", owner='" + owner + '\'' +
                ", name='" + name + '\'' +
                ", versions=" + versions +
                ", partition='" + partition + '\'' +
                '}';
    }
}
