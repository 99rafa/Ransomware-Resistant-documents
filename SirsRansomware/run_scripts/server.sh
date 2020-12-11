#! /bin/bash

LOCALPATH=$(pwd)

# Server initialization

mvn exec:java -Dexec.mainClass="server.Server" -Dexec.args="mateus pass 2181 192.168.0.100 8085 192.168.0.100 $LOCALPATH/src/assets/certs/server.pem $LOCALPATH/src/assets/certs/server.key $LOCALPATH/src/assets/certs/ca.pem"
