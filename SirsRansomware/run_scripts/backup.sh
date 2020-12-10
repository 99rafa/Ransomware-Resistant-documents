#! /bin/bash

LOCALPATH=$(pwd)

# Backup initialization

mvn exec:java -Dexec.mainClass="server.BackupServer" -Dexec.args="1 1 2181 192.168.0.100 8086 192.168.0.200 $LOCALPATH/src/assets/certs/server1.pem $LOCALPATH/src/assets/certs/server1.key $LOCALPATH/src/assets/certs/ca.pem"
