package server.domain.file;


import server.database.Repository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class FileRepository extends Repository {

    public FileRepository(Connection c) {
        super(c);
    }

    public boolean fileExists(String uid){
        try {
            String sql = "SELECT uid FROM Files WHERE uid = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, uid);

            ResultSet rs = statement.executeQuery();
            if(rs.next()) return true;

        }catch (SQLException e){
            e.printStackTrace();
        }
        return false;
    }

    public File getFileByUID(String uid){
        File file = new File();
        List<String> versions = new ArrayList<>();
        try {
            String sql = "SELECT uid,owner,name,part_id FROM Files WHERE uid = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, uid);

            ResultSet rs = statement.executeQuery();
            while (rs.next()) {
                file.setUid(uid);
                file.setOwner(rs.getString("owner"));
                file.setName(rs.getString("name"));
                file.setPartition(rs.getString("part_id"));
            }

            sql = "SELECT version_uid FROM FileVersions WHERE file_uid = ?";
            statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, uid);

            rs = statement.executeQuery();
            while (rs.next()) {
                versions.add(rs.getString("version_uid"));
            }
            file.setVersions(versions);

        }catch (SQLException e){
            e.printStackTrace();
        }
        return file;
    }
}
