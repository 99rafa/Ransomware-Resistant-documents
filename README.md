# SIRS_proj1
1st project for SIRS course - MEIC-A


READ ME BONITO POR FAZER TOP TOP

# Server command
mvn exec:java -Dexec.mainClass="server.Server" -Dexec.args="1 2181 localhost 8085 localhost {LOCALPATH}/SirsRansomware/src/assets/certs/server1.pem 
{LOCALPATH}/SirsRansomware/src/assets/certs/server1.key"

# Client Script

mvn exec:java -Dexec.mainClass="client.Client" -Dexec.args="localhost 2181  {LOCALPATH}/SirsRansomware/src/assets/certs/ca.pem"
