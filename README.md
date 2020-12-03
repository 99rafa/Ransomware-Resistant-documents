# SIRS_proj1 - Ransomware Resistant Documents
1st project for SIRS course - MEIC-A, Group 39:
- Afonso Paredes, ist189401
- Mateus Monteiro, ist189506
- Rafael Alexandre, ist189528

## Setup

Our software was developed in **java** and built with **maven**.


## Running

In order to run the program, at least 3 terminal windows must be open:
- 1 server
- 1+ backup server(s)
- 1 client


#### Server initialization

Assuming `$LOCALPATH` is the root directory of the project,

```mvn exec:java -Dexec.mainClass="server.Server" -Dexec.args="<zooPort> <zooHost> <serverPort> <serverHost> $LOCALPATH/<path-to-trust-certificate> $LOCALPATH/<path-to-server-private-key> $LOCALPATH/<path-ca-certificate>" ```

- **zooPort**:
- **zooHost**:
- **serverPort**:
- **serverHost**:
- **path-to-cert-certificate**:
- **path-to-server-private-key**:
- **path-to-ca-certificate**:

#### Backup Server initialization

```mvn exec:java -Dexec.mainClass="server.Server" -Dexec.args="<partitionID> <serverID> <zooPort> <zooHost> <serverPort> <serverHost> $LOCALPATH/<path-to-trust-certificate> $LOCALPATH/<path-to-server-private-key> $LOCALPATH/<path-ca-certificate>" ```

- **partitionID**:
- **serverID**:
- **zooPort**:
- **zooHost**:
- **serverPort**:
- **serverHost**:
- **path-to-cert-certificate**:
- **path-to-server-private-key**:
- **path-to-ca-certificate**:


#### Client Initialization

```mvn exec:java -Dexec.mainClass="client.Client" -Dexec.args="<zooPort> <zooHost> $LOCALPATH/<path-to-trust-certificate> $LOCALPATH/<path-to-client-private-key> $LOCALPATH/<path-ca-certificate>" ```

- **zooPort**:
- **zooHost**:
- **path-to-cert-certificate**:
- **path-to-client-private-key**:
- **path-to-ca-certificate**:
