package server.domain.fileVersion;


import server.database.Connector;
import server.database.DatabaseObject;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;

public class FileVersion implements DatabaseObject {

    //PK
    private String versionUid;
    private String fileUid;
    private String creator;
    private Date date;
    private byte[] digitalSignature;

    public FileVersion(String versionUid, String fileUid, String creator, Date date, byte[] digitalSignature) {
        this.versionUid = versionUid;
        this.fileUid = fileUid;
        this.creator = creator;
        this.date = date;
        this.digitalSignature = digitalSignature;
    }

    public FileVersion() {
    }

    public String getCreator() {
        return creator;
    }

    public void setCreator(String creator) {
        this.creator = creator;
    }

    public String getVersionUid() {
        return versionUid;
    }

    public void setVersionUid(String versionUid) {
        this.versionUid = versionUid;
    }

    public String getFileUid() {
        return fileUid;
    }

    public void setFileUid(String fileUid) {
        this.fileUid = fileUid;
    }

    public void setUid(String uid) {
        this.versionUid = uid;
    }

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }

    @Override
    public void saveInDatabase(Connector connector) {
        try {
            //Prepared statement
            String sql = "INSERT INTO FileVersions VALUES (?,?,?,?,?)";
            PreparedStatement s = connector.connection.prepareStatement(sql);

            //Set parameters
            s.setString(1, this.versionUid);
            s.setString(2, this.fileUid);
            s.setString(3, this.creator);
            s.setTimestamp(4, new Timestamp(this.date.getTime()));
            s.setBytes(5,this.digitalSignature);
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
        return "FileVersion{" +
                "versionUid='" + versionUid + '\'' +
                ", fileUid='" + fileUid + '\'' +
                ", creator='" + creator + '\'' +
                ", date=" + date +
                '}';
    }

    public byte[] getDigitalSignature() {
        return digitalSignature;
    }

    public void setDigitalSignature(byte[] digitalSignature) {
        this.digitalSignature = digitalSignature;
    }
}
