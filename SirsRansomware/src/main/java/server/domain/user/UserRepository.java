package server.domain.user;

import server.database.Repository;

import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class UserRepository extends Repository {

    public UserRepository(Connection c) {
        super(c);
    }

    public byte[] getUserPassword(String username){
        byte[] userPassword = null;
        try {

            String sql = "SELECT password FROM Users WHERE username = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters

            statement.setString(1, username);

            ResultSet rs = statement.executeQuery();

            if (rs.next()){
                userPassword = rs.getBytes("password");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return userPassword;
    }

    public User getUserByUsername(String username){
        User user = new User();
        List<String> readableFiles = new ArrayList<>();
        List<String> editableFiles = new ArrayList<>();
        List<String> ownedFiles = new ArrayList<>();
        List<String> createdVersions = new ArrayList<>();
        try {

            String sql = "SELECT username,password FROM Users WHERE username = ?";
            PreparedStatement statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1,username);

            ResultSet rs = statement.executeQuery();
            while(rs.next()){
                //Retrieve by column name
                user.setUsername(username);
                user.setPassHash(rs.getBytes("password"));
            }

            //Retrieve owned files
            sql = "SELECT uid FROM Files WHERE owner = ?";
            statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1,username);

            rs = statement.executeQuery();

            while(rs.next()) ownedFiles.add(rs.getString("uid"));

            user.setOwnedFiles(ownedFiles);


            //Retrieve editable files
            sql = "SELECT uid FROM EditableFiles WHERE username = ?";
            statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1,username);

            rs = statement.executeQuery();

            while(rs.next()) editableFiles.add(rs.getString("uid"));

            user.setEditableFiles(editableFiles);

            //Retrieve readable files
            sql = "SELECT uid FROM ReadableFiles WHERE username = ?";
            statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1,username);

            rs = statement.executeQuery();

            while(rs.next()) readableFiles.add(rs.getString("uid"));

            user.setReadableFiles(readableFiles);

            //Retrieve created versions
            sql = "SELECT version_uid FROM FileVersions WHERE creator = ?";
            statement = super.getConnection().prepareStatement(sql);

            //Set parameters
            statement.setString(1,username);

            rs = statement.executeQuery();

            while(rs.next()) createdVersions.add(rs.getString("version_uid"));

            user.setCreatedVersions(createdVersions);

        } catch (SQLException e) {
            e.printStackTrace();
        }
        return user;
    }
}
