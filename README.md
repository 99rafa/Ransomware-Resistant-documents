# SIRS_proj1
1st project for SIRS course - MEIC-A


# Server initialization

mvn exec:java -Dexec.mainClass="server.Server" -Dexec.args="1 2181 localhost 8085 localhost {LOCALPATH}/SirsRansomware/src/assets/certs/server1.pem {LOCALPATH}/SirsRansomware/src/assets/certs/server1.key {LOCALPATH}/SirsRansomware/src/assets/certs/ca.pem

# Client Initialization

mvn exec:java -Dexec.mainClass="client.Client" -Dexec.args="localhost 2181 {LOCALPATH}/SirsRansomware/src/assets/certs/ca.pem {LOCALPATH}/SirsRansomware/src/assets/certs/server1.pem {LOCALPATH}/SirsRansomware/src/assets/certs/server1.key"
