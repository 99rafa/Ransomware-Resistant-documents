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

    public byte[] getPasswordSalt(String username) {
        byte[] passSalt = null;
        try {

            String sql = "SELECT salt FROM Users WHERE username = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters

            statement.setString(1, username);

            ResultSet rs = statement.executeQuery();

            if (rs.next()) {
                passSalt = rs.getBytes("salt");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return passSalt;
    }

    public int getPasswordIterations(String username) {
        int passIterations = 0;
        try {

            String sql = "SELECT iterations FROM Users WHERE username = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters

            statement.setString(1, username);

            ResultSet rs = statement.executeQuery();

            if (rs.next()) {
                passIterations = rs.getInt("iterations");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return passIterations;
    }

    public void setUserPermissionFile(String username, String uid, String mode) {
        switch (mode) {
            case "read" -> addUserToReadableFiles(username, uid);
            case "write" -> {
                addUserToEditableFiles(username, uid);
                addUserToReadableFiles(username, uid);
            }
            default -> System.out.println("It should not happen");
        }
    }

    public void addUserToEditableFiles(String username, String uid) {
        try {

            String sql = "INSERT INTO EditableFiles VALUES (?,?)";
            PreparedStatement s = super.getConnection().prepareStatement(sql);

            s.setString(1, username);
            s.setString(2, uid);
            s.executeUpdate();

            super.getConnection().commit();
        } catch (SQLException e) {
            e.printStackTrace();
            //Rollback changes in case of failure
            try {
                super.getConnection().rollback();
            } catch (SQLException ignored) {}
        }
    }

    public void addUserToReadableFiles(String username, String uid) {
        try {

            String sql = "INSERT INTO ReadableFiles VALUES (?,?)";
            PreparedStatement s = super.getConnection().prepareStatement(sql);

            s.setString(1, username);
            s.setString(2, uid);
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
    public List<String> getUsersWithPermissions(String uid, String mode) {
        List<String> usernames= new ArrayList<>();
        if (mode.equals("read")) {
            try {

                String sql = "SELECT username FROM ReadableFiles WHERE uid = ?";
                PreparedStatement s = super.getConnection().prepareStatement(sql);
                s.setString(1, uid);

                ResultSet rs = s.executeQuery();
                while (rs.next()) {
                    usernames.add(rs.getString("username"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        else if (mode.equals("write")) {
            try {

                String sql = "SELECT username FROM EditableFiles WHERE uid = ?";
                PreparedStatement s = super.getConnection().prepareStatement(sql);
                s.setString(1, uid);

                ResultSet rs = s.executeQuery();
                while (rs.next()) {
                    usernames.add(rs.getString("username"));
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        else {
            System.out.println("Não pode acontecer");
        }
        return usernames;
    }


    public User getUserByUsername(String username) {
        User user = new User();
        List<String> readableFiles = new ArrayList<>();
        List<String> editableFiles = new ArrayList<>();
        List<String> ownedFiles = new ArrayList<>();
        List<String> createdVersions = new ArrayList<>();
        try {

            String sql = "SELECT username,password,salt FROM Users WHERE username = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1, username);

            ResultSet rs = statement.executeQuery();
            while (rs.next()) {
                //Retrieve by column name
                user.setUsername(username);
                user.setPassHash(rs.getBytes("password"));
                user.setSalt(rs.getBytes("salt"));
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
