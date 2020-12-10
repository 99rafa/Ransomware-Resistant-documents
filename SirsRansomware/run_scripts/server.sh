#! /bin/bash

LOCALPATH=$(pwd)

# Server initialization

mvn exec:java -Dexec.mainClass="server.Server" -Dexec.args="2181 192.168.0.100 8085 192.168.0.100 $LOCALPATH/src/assets/certs/server1.pem $LOCALPATH/src/assets/certs/server1.key $LOCALPATH/src/assets/certs/ca.pem"
