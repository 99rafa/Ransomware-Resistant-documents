# SIRS_proj1
1st project for SIRS course - MEIC-A


LOCALPATH=$(pwd)

# Server initialization

mvn exec:java -Dexec.mainClass="server.Server" -Dexec.args="1 1 2181 localhost 8085 localhost $LOCALPATH/src/assets/certs/server1.pem $LOCALPATH/src/assets/certs/server1.key $LOCALPATH/src/assets/certs/ca.pem"

# Client Initialization

mvn exec:java -Dexec.mainClass="client.Client" -Dexec.args="localhost 2181 $LOCALPATH/src/assets/certs/ca.pem $LOCALPATH/SirsRansomware/src/assets/certs/server1.pem $LOCALPATH/src/assets/certs/server1.key"
