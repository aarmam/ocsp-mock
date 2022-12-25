# OCSP responder service

Mock OCSP responder

- [Prerequisites](#prerequisites)
- [Build application](#build)
- [Run application](#run)
- [Build docker image](#build-docker)


<a name="prerequisites"></a>
## Prerequisites

* Java 17 JDK

<a name="build"></a>
## Build application

```Shell
./mvnw clean package
```

<a name="run"></a>
## Run application

```Shell
java -jar target/ocsp-mock-{version}.jar
```
<a name="build-docker"></a>
## Build docker image

```Shell
./mvnw clean spring-boot:build-image
```

<a name="run-docker"></a>
## Run docker image

```Shell
docker run -p 8080:8080 ocsp-mock:latest
```