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
- ZooKeeper name Server / zkNaming


## Usage

In order to run the program, at least 3 terminal windows must be open:
- 1 server
- 1+ backup server(s)
- 1 client

#### 0. Installing and compiling project 

Run script **init.sh** to install and compile the project 

#### 1. Server initialization

Assuming `$LOCALPATH` is the root directory of the project,

```bash
mvn exec:java -Dexec.mainClass="server.Server" -Dexec.args="<zooPort> <zooHost> <serverPort> <serverHost> $LOCALPATH/<path-to-trust-certificate> $LOCALPATH/<path-to-server-private-key> $LOCALPATH/<path-to-certificate-authority>" 
```

- **zooPort**: zookeeper(port)
- **zooHost**: zookeeper(host)
- **serverPort**: server(port)
- **serverHost**: server(host)
- **path-to-trust-certificate**: path to the trustable server's certificate
- **path-to-server-private-key**: path to the server's private key
- **path-to-certificate-authority**: path to the certificate authority

#### 2. Backup Server initialization

```bash
mvn exec:java -Dexec.mainClass="server.BackupServer" -Dexec.args="<partitionID> <serverID> <zooPort> <zooHost> <backupServerPort> <backupServerHost> $LOCALPATH/<path-to-trust-certificate> $LOCALPATH/<path-to-backupServer-private-key> $LOCALPATH/<path-to-certificate-authority>" 
```

- **partitionID**: Id of the partition(integer)
- **serverID**: Id of the server(integer)
- **zooPort**: zookeeper(port)
- **zooHost**: zookeeper(host)
- **backupServerPort**: backupServer(port)
- **backupServerHost**: backupServer(host)
- **path-to-trust-certificate**: path to the trustable backup server's certificate
- **path-to-server-private-key**: path to the backup server's private key
- **path-to-certificate-authority**:path to the certificate authority


#### 3. Client Initialization
```bash
mvn exec:java -Dexec.mainClass="client.Client" -Dexec.args="<zooPort> <zooHost> $LOCALPATH/<path-to-trust-certificate> $LOCALPATH/<path-to-client-private-key> $LOCALPATH/<path-to-certificate-authority>" 
```

- **zooPort**: zookeeper(port)
- **zooHost**: zookeeper(host)
- **path-to-trust-certificate**: path to the trustable client's certificate
- **path-to-client-private-key**: path to the client's private key
- **path-to-certificate-authority**:path to the certificate authority


