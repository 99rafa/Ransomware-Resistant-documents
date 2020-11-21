package server.domain.fileVersion;

import server.database.Repository;

import java.sql.Connection;

public class FileVersionRepository extends Repository {

    public FileVersionRepository(Connection c) {
        super(c);
    }

    public FileVersion getFileVersionByUID(String uid){
        return null;
    }
}
