#! /bin/bash

LOCALPATH=$(pwd)

# Backup initialization

mvn exec:java -Dexec.mainClass="server.BackupServer" -Dexec.args="1 1 2181 localhost 8086 localhost $LOCALPATH/src/assets/certs/server1.pem $LOCALPATH/src/assets/certs/server1.key $LOCALPATH/src/assets/certs/ca.pem"
