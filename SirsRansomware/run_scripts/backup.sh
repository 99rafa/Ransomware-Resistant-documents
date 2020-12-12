#! /bin/bash

LOCALPATH=$(pwd)

# Backup initialization

mvn exec:java -Dexec.mainClass="server.BackupServer" -Dexec.args="1 1 2181 192.168.0.100 8086 192.168.0.200"
