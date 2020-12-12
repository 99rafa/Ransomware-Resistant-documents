package server.domain.user;

import server.database.Repository;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class UserRepository extends Repository {

    public UserRepository(Connection c) {
        super(c);
    }

    public byte[] getUserPassword(String username) {
        byte[] userPassword = null;
        try {
            String sql = "SELECT password FROM Users WHERE username = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters

            statement.setString(1, username);

            ResultSet rs = statement.executeQuery();

            if (rs.next()) {
                userPassword = rs.getBytes("password");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return userPassword;
    }

    private boolean userAllowed(String username , String uid, String mode){
        try {
            String sql = "";

            if (mode.equals("write")) {
                sql = "SELECT * FROM EditableFiles WHERE uid = ? and username= ?";
            }
            else if (mode.equals("read")) {
                sql = "SELECT * FROM ReadableFiles WHERE uid = ? and username= ?";


            }

            PreparedStatement  statement = super.getConnection().prepareStatement(sql);
            statement.setString(1, uid);
            statement.setString(2, username);

            ResultSet rs = statement.executeQuery();
            return rs.next();

        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }

    }

    public void setUserPermissionFile(String username, String uid, String mode, byte[] AESEncrypted) {

        switch (mode) {
            case "read" -> { if (!userAllowed(username,uid,mode)){ addUserToReadableFiles(username, uid, AESEncrypted);}
            }
            case "write" -> {
                if (!userAllowed(username,uid,mode)) addUserToEditableFiles(username, uid, AESEncrypted);
                if (!userAllowed(username,uid,"read")) addUserToReadableFiles(username, uid, AESEncrypted);
            }
            default -> System.out.println("It should not happen");
        }
    }


    public void addUserToEditableFiles(String username, String uid, byte[] AESEncrypted) {
        try {
            String sql = "INSERT INTO EditableFiles VALUES (?,?,?)";
            PreparedStatement s = super.getConnection().prepareStatement(sql);

            s.setString(1, username);
            s.setString(2, uid);
            s.setBytes(3, AESEncrypted);
            s.executeUpdate();

            super.getConnection().commit();
        } catch (SQLException e) {
            e.printStackTrace();
            //Rollback changes in case of failure
            try {
                super.getConnection().rollback();
            } catch (SQLException ignored) {
            }
        }
    }



    public void addUserToReadableFiles(String username, String uid, byte[] AESEncrypted) {
        try {

            String sql = "INSERT INTO ReadableFiles VALUES (?,?,?)";
            PreparedStatement s = super.getConnection().prepareStatement(sql);


            s.setString(1, username);
            s.setString(2, uid);
            s.setBytes(3, AESEncrypted);
            s.executeUpdate();

            super.getConnection().commit();
        } catch (SQLException e) {
            e.printStackTrace();
            //Rollback changes in case of failure
            try {
                super.getConnection().rollback();
            } catch (SQLException ignored) {
            }
        }
    }

    public boolean isOwner(String username, String uid) {
        boolean bool = false;
        try {
            String sql = "SELECT owner FROM Files WHERE uid = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, uid);

            ResultSet rs = statement.executeQuery();
            while (rs.next()) {
                if (rs.getString("owner").equals(username)) {
                    bool = true;
                }
            }


        } catch (SQLException e) {
            e.printStackTrace();
        }
        return bool;

    }

    public List<byte[]> getPublicKeysByUsernames(List<String> usernames) {
        List<byte[]> publicKeys = new ArrayList<>();
        for (String username : usernames) {
            try {

                String sql = "SELECT public_key FROM Users WHERE username = ?";
                PreparedStatement statement = super.getConnection().prepareStatement(sql);

                //Set parameters

                statement.setString(1, username);

                ResultSet rs = statement.executeQuery();

                if (rs.next()) {
                    publicKeys.add(rs.getBytes("public_key"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        return publicKeys;
    }

    public User getUserByUsername(String username) {
        User user = new User();
        List<String> readableFiles = new ArrayList<>();
        List<String> editableFiles = new ArrayList<>();
        List<String> ownedFiles = new ArrayList<>();
        List<String> createdVersions = new ArrayList<>();
        try {

            String sql = "SELECT username,password,salt,public_key FROM Users WHERE username = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, username);

            ResultSet rs = statement.executeQuery();
            while (rs.next()) {
                //Retrieve by column name
                user.setUsername(username);
                user.setPassHash(rs.getBytes("password"));
                user.setSalt(rs.getBytes("salt"));
                user.setPublicKey(rs.getBytes("public_key"));
            }

            //Retrieve owned files
            sql = "SELECT uid FROM Files WHERE owner = ?";
            statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, username);

            rs = statement.executeQuery();

            while (rs.next()) ownedFiles.add(rs.getString("uid"));

            user.setOwnedFiles(ownedFiles);


            //Retrieve editable files
            sql = "SELECT uid FROM EditableFiles WHERE username = ?";
            statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, username);

            rs = statement.executeQuery();

            while (rs.next()) editableFiles.add(rs.getString("uid"));

            user.setEditableFiles(editableFiles);

            //Retrieve readable files
            sql = "SELECT uid FROM ReadableFiles WHERE username = ?";
            statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, username);

            rs = statement.executeQuery();

            while (rs.next()) readableFiles.add(rs.getString("uid"));

            user.setReadableFiles(readableFiles);

            //Retrieve created versions
            sql = "SELECT version_uid FROM FileVersions WHERE creator = ?";
            statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, username);

            rs = statement.executeQuery();

            while (rs.next()) createdVersions.add(rs.getString("version_uid"));

            user.setCreatedVersions(createdVersions);

        } catch (SQLException e) {
            e.printStackTrace();
        }
        return user;
    }
}
