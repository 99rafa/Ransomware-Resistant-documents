# Naming 

Set of libraries to interact with Naming servers.

Developed at **I**nstituto **S**uperior **T**écnico, Universidade de Lisboa, Portugal

The UDDI-Naming library provides a JAX-R wrapper that emulates JNDI Naming interface with _bind_ and _lookup_ operations.

The ZK-Naming library provides a ZooKeeper client wrapper that also emulates _bind_ and _lookup_.


## Getting Started

Naming servers are used to register names and their values.
Usually they translate an human-friendly identifier to a system-internal, often numeric identification or addressing component.

A naming library is intended to simplify the use of naming servers in application code.

The two typical operations are:

* _bind(name, value)_ - associate the name with the given value
* _value lookup(name)_ - search for the name and return its value
 

### Prerequisites

Java Developer Kit 8 is required running on Linux, Windows or Mac.
Maven 3 is also required.

To confirm that you have them installed, open a terminal and type:

```
javac -version

mvn -version
```

For UDDI-Naming, a [jUDDI](https://juddi.apache.org/) server is required.  
You can find a version of jUDDI configured to use port 9090 at the [Distributed Systems course page (in Portuguese)](http://disciplinas.tecnico.ulisboa.pt/leic-sod/2017-2018/labs/software/index.html).

For ZK-Naming, [ZooKeeper](https://zookeeper.apache.org/) server is required.


### Installing

To compile and install all modules:

```
mvn clean install -DskipTests
```

The tests are skipped because they require the server to be running.


<!--
## Deployment

Add additional notes about how to deploy this on a live system
-->

## Built With

* [Maven](https://maven.apache.org/) - Build Tool and Dependency Management

<!--
## Contributing

Please read [CONTRIBUTING.md](https://gist.github.com/PurpleBooth/b24679402957c63ec426) for details on our code of conduct, and the process for submitting pull requests to us.
-->


## Versioning

We use [SemVer](http://semver.org/) for versioning. 

<!--
For the versions available, see the [tags on this repository](https://github.com/your/project/tags). 
-->

## Authors

* **Miguel L. Pardal** - *Design and implementation* - [miguelpardal](https://github.com/miguelpardal)
* **Rui Claro** - *ZK-Naming implementation* - [RuiClaro](https://github.com/RuiClaro)

See also the list of [contributors](https://github.com/tecnico-distsys/naming/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* All the Distributed Systems students for their feedback
* Other members of the Distributed Systems teaching staff

