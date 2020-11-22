package server.domain.fileVersion;

import server.database.Repository;
import server.domain.file.File;

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

    public FileVersion getFileVersionByUID(String uid){

        FileVersion version = new FileVersion();
        try {
            String sql = "SELECT version_uid,file_uid,creator,date FROM FileVersions WHERE version_uid = ?";
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

        }catch (SQLException e){
            e.printStackTrace();
        }
        return version;
    }
}
