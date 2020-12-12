#! /bin/bash

LOCALPATH=$(pwd)

# Backup 2 initialization

mvn exec:java -Dexec.mainClass="server.BackupServer" -Dexec.args="1 2 2181 192.168.0.100 8087 192.168.0.151"
