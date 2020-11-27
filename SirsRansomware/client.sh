#! /bin/bash
LOCALPATH=$(pwd)

# Client Initialization

mvn exec:java -Dexec.mainClass="client.Client" -Dexec.args="localhost 2181 $LOCALPATH/src/assets/certs/ca.pem $LOCALPATH/src/assets/certs/server1.pem $LOCALPATH/src/assets/certs/server1.key"
