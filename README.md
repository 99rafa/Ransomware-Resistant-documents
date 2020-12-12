# SIRS project - Ransomware Resistant Documents
1st project for SIRS course - MEIC-A, Group 39:
- Afonso Paredes, ist189401
- Mateus Monteiro, ist189506
- Rafael Alexandre, ist189528

## Setup

#### Requirements

The requirements needed to run the program are:
- Linux 64-bit (whichever distribution the user prefers, although we recommend Ubuntu 18.04.1 LTS)
- Java 15
- Maven
- MySQL 
- ZooKeeper name Server/zkNaming


## Usage

In order to run the program, at least 3 terminal windows must be open:
- 1 server
- 1+ backup server(s)
- 1 client

#### 0. Installing and compiling project 


1. Open `zookeeper/bin` folder and run the command `./zkServer.sh start` to launch the ZooKeeper name server. If you wish to stop Zookeper name server, you can run `./zkServer.sh stop`.

2. Run `mysql.server start`. Then, create the database in which the data will be stored, running the command `createdb <name-of-db>` where `<name-of-db>` is the desired name for the databse. Afterwards, Open `<root-project-directory>/src/assets/sql_scripts>` and run `mysql <name-of-db> -p < init.sql` to initialize the databse.

3. Open `<root-project-directory>/run_scripts` and run script **init.sh** to install and compile the whole project.

#### 1. Server initialization

Run

```bash
mvn exec:java -Dexec.mainClass="server.Server" -Dexec.args="<zooPort> <zooHost> <serverPort> <serverHost>" 
```

- **zooPort**: zookeeper(port)
- **zooHost**: zookeeper(host)
- **serverPort**: server(port)
- **serverHost**: server(host)

Alternatively, open `<root-project-directory>/run_scripts` and run script **server.sh** to run the server program.

#### 2. Backup Server initialization

Run

```bash
mvn exec:java -Dexec.mainClass="server.BackupServer" -Dexec.args="<partitionID> <serverID> <zooPort> <zooHost> <backupServerPort> <backupServerHost>" 
```

- **partitionID**: Id of the partition(integer)
- **serverID**: Id of the server(integer)
- **zooPort**: zookeeper(port)
- **zooHost**: zookeeper(host)
- **backupServerPort**: backupServer(port)
- **backupServerHost**: backupServer(host)

Alternatively, open `<root-project-directory>/run_scripts` and run script **backup.sh** to run the backup server program.


#### 3. Client Initialization

Run,
```bash
mvn exec:java -Dexec.mainClass="client.Client" -Dexec.args="<zooPort> <zooHost>" 
```

- **zooPort**: zookeeper(port)
- **zooHost**: zookeeper(host)

Alternatively, open `<root-project-directory>/run_scripts` and run script **client.sh** to run the client program.


