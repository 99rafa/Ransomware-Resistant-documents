#! /bin/bash
LOCALPATH=$(pwd)

# Client Initialization

mvn exec:java -Dexec.mainClass="client.Client" -Dexec.args="192.168.0.100 2181 $LOCALPATH/src/assets/certs/ca.pem $LOCALPATH/src/assets/certs/client.pem $LOCALPATH/src/assets/certs/client.key"
