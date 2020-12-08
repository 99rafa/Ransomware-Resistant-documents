package server.domain.fileVersion;

import server.database.Repository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class FileVersionRepository extends Repository {

    public FileVersionRepository(Connection c) {
        super(c);
    }

    public List<FileVersion> getFileVersions(String uid) {
        List<FileVersion> versions = new ArrayList<>() {
        };
        try {
            String sql = "SELECT version_uid,file_uid,digital_signature,creator,ts FROM FileVersions WHERE file_uid = ? ORDER BY ts DESC";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, uid);

            ResultSet rs = statement.executeQuery();
            while (rs.next()) {
                FileVersion version = new FileVersion();
                version.setVersionUid(rs.getString("version_uid"));
                version.setFileUid(uid);
                version.setCreator(rs.getString("creator"));
                version.setDate(rs.getTimestamp("ts"));
                version.setDigitalSignature(rs.getBytes("digital_signature"));
                versions.add(version);
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }
        return versions;
    }


    public FileVersion getMostRecentVersion(String fileUid) {
        FileVersion version = new FileVersion();
        try {
            String sql = "SELECT version_uid,file_uid,digital_signature,creator,ts FROM FileVersions WHERE file_uid = ? ORDER BY date DESC LIMIT 1";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, fileUid);

            ResultSet rs = statement.executeQuery();
            while (rs.next()) {
                version.setVersionUid(rs.getString("version_uid"));
                version.setFileUid(fileUid);
                version.setCreator(rs.getString("creator"));
                version.setDate(rs.getDate("ts"));
                version.setDigitalSignature(rs.getBytes("digital_signature"));
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }
        return version;
    }
}
