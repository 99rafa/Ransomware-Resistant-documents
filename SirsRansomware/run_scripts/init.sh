#! /bin/bash

# Install and compile project
cd ..
mvn clean
mvn install
mvn compile
cd run_scripts/
