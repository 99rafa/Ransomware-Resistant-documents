#! /bin/bash

LOCALPATH=$(pwd)

# Backup 1 initialization

mvn exec:java -Dexec.mainClass="server.BackupServer" -Dexec.args="1 2 2181 192.168.0.100 8086 192.168.0.201 $LOCALPATH/src/assets/certs/server.pem $LOCALPATH/src/assets/certs/server.key $LOCALPATH/src/assets/certs/ca.pem"
