DROP TABLE IF EXISTS EditableFiles;
DROP TABLE IF EXISTS ReadableFiles;
DROP TABLE IF EXISTS FileVersions;
DROP TABLE IF EXISTS Files;
DROP TABLE IF EXISTS Users;

CREATE TABLE Users (
   username VARCHAR(15) PRIMARY KEY,
   password VARBINARY(1024) NOT NULL
);

CREATE TABLE Files (
   uid VARCHAR(30) PRIMARY KEY,
   owner VARCHAR(30) NOT NULL,
   name VARCHAR(30) NOT NULL,
   part_id VARCHAR(30) NOT NULL,
   FOREIGN KEY (owner) REFERENCES Users(username)
);

CREATE TABLE FileVersions (
   version_uid VARCHAR(30) PRIMARY KEY,
   file_uid VARCHAR(30) NOT NULL,
   creator VARCHAR(30) NOT NULL ,
   path VARCHAR(100) NOT NULL,
   date DATETIME NOT NULL,
   FOREIGN KEY (file_uid) REFERENCES Files(uid),
   FOREIGN KEY (creator) REFERENCES Users(username)
);

CREATE TABLE EditableFiles(
    username VARCHAR(15),
    uid VARCHAR(30),
    FOREIGN KEY (username) REFERENCES Users(username),
    FOREIGN KEY (uid) REFERENCES Files(uid)
);

CREATE TABLE ReadableFiles(
    username VARCHAR(15),
    uid VARCHAR(30),
    FOREIGN KEY (username) REFERENCES Users(username),
    FOREIGN KEY (uid) REFERENCES Files(uid)
);