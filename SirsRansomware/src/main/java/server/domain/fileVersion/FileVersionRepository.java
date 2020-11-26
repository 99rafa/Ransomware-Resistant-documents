package server.domain.fileVersion;

import server.database.Repository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class FileVersionRepository extends Repository {

    public FileVersionRepository(Connection c) {
        super(c);
    }

    public FileVersion getFileVersionByUID(String uid) {

        FileVersion version = new FileVersion();
        try {
            String sql = "SELECT version_uid,file_uid,digital_signature,creator,date FROM FileVersions WHERE version_uid = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, uid);

            ResultSet rs = statement.executeQuery();
            while (rs.next()) {
                version.setVersionUid(uid);
                version.setFileUid(rs.getString("file_uid"));
                version.setCreator(rs.getString("creator"));
                version.setDate(rs.getDate("date"));
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }
        return version;
    }

    public FileVersion getMostRecentVersion(String fileUid) {
        FileVersion version = new FileVersion();
        try {
            String sql = "SELECT version_uid,file_uid,digital_signature,creator,date FROM FileVersions WHERE file_uid = ? ORDER BY date DESC LIMIT 1";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, fileUid);

            ResultSet rs = statement.executeQuery();
            while (rs.next()) {
                version.setVersionUid(rs.getString("version_uid"));
                version.setFileUid(fileUid);
                version.setCreator(rs.getString("creator"));
                version.setDate(rs.getDate("date"));
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }
        return version;
    }
}
