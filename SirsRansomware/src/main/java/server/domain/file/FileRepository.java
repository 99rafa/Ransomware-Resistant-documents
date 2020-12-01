package server.domain.file;


import com.google.protobuf.ByteString;
import server.database.Repository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class FileRepository extends Repository {

    public FileRepository(Connection c) {
        super(c);
    }

    public boolean fileExists(String uid) {
        try {
            String sql = "SELECT uid FROM Files WHERE uid = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, uid);

            ResultSet rs = statement.executeQuery();
            if (rs.next()) return true;

        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public File getFileByUID(String uid) {
        File file = new File();
        List<String> versions = new ArrayList<>();
        try {
            String sql = "SELECT uid,owner,name,part_id,iv FROM Files WHERE uid = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, uid);

            ResultSet rs = statement.executeQuery();
            while (rs.next()) {
                file.setUid(uid);
                file.setOwner(rs.getString("owner"));
                file.setName(rs.getString("name"));
                file.setPartition(rs.getString("part_id"));
                file.setIv(rs.getBytes("iv"));
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

        } catch (SQLException e) {
            e.printStackTrace();
        }
        return file;
    }

    public List<byte[]> getPublicKeysByFile(String uid){
        List<byte[]> publicKeys = new ArrayList<>();
        List<String> usernames = new ArrayList<>();
        try {

            String sql = "SELECT username FROM ReadableFiles WHERE uid = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters

            statement.setString(1, uid);

            ResultSet rs = statement.executeQuery();

            if (rs.next()) {
                usernames.add(rs.getString("username"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        for(String username : usernames){
            try {

                String sql = "SELECT public_key FROM Users WHERE username = ?";
                PreparedStatement statement = super.getConnection().prepareStatement(sql);

                //Set parameters

                statement.setString(1, username);

                ResultSet rs = statement.executeQuery();

                if (rs.next()) {
                    publicKeys.add(rs.getBytes(""));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        return publicKeys;
    }

    public byte[] getFileOwnerPublicKey(String uid){
        try {
            String owner = "";
            String sql = "SELECT creator FROM FileVersions WHERE version_uid = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters

            statement.setString(1, uid);

            ResultSet rs = statement.executeQuery();

            if (rs.next()) {
                owner = rs.getString("creator");
            }
            sql = "SELECT public_key FROM Users WHERE username = ?";
            statement = super.getConnection().prepareStatement(sql);

            //Set parameters

            statement.setString(1, owner);

            rs = statement.executeQuery();

            if (rs.next()) {
                return rs.getBytes("public_key");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] getFileIv(String uid){
        try {
            String sql = "SELECT iv FROM Files WHERE uid = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, uid);

            ResultSet rs = statement.executeQuery();
            if (rs.next()) return rs.getBytes("iv");

        } catch (SQLException e) {
            e.printStackTrace();
        }
        return new byte[0];
    }

    public List<File> getUserReadableFiles(String username) {
        List<File> files = new ArrayList<>();
        try {
            String sql = "SELECT Files.uid,owner,name,part_id,iv FROM Files,ReadableFiles WHERE Files.uid = ReadableFiles.uid AND username = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, username);

            ResultSet rs = statement.executeQuery();
            while (rs.next()) {
                File file = new File();
                file.setUid(rs.getString("uid"));
                file.setOwner(rs.getString("owner"));
                file.setName(rs.getString("name"));
                file.setPartition(rs.getString("part_id"));
                file.setIv(rs.getBytes("iv"));
                files.add(file);
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }
        return files;
    }


    public byte[] getAESEncrypted(String username, String uid){
        byte[] aes=null;
        try{
            String sql = "SELECT AESEncrypted FROM ReadableFiles WHERE username= ? AND uid= ? ";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);
            statement.setString(1, username);
            statement.setString(2, uid);

            ResultSet rs = statement.executeQuery();

            while (rs.next()) {
                aes = rs.getBytes("AESEncrypted");
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }
        return aes;
    }

    public List<File> getUserEditableFiles(String username) {
        List<File> files = new ArrayList<>();
        try {
            String sql = "SELECT Files.uid,owner,name,part_id FROM Files,EditableFiles WHERE Files.uid = EditableFiles.uid AND username = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, username);

            ResultSet rs = statement.executeQuery();
            while (rs.next()) {
                File file = new File();
                file.setUid(rs.getString("uid"));
                file.setOwner(rs.getString("owner"));
                file.setName(rs.getString("name"));
                file.setPartition(rs.getString("part_id"));
                files.add(file);
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }
        return files;
    }
}
