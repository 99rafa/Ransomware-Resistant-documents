package server.domain.file;


import server.database.Repository;

import java.sql.Connection;

public class FileRepository extends Repository {

    public FileRepository(Connection c) {
        super(c);
    }

    public File getFileByUID(String uid){

        return null;
    }
}
