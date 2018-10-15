FROM        openjdk:8-jdk-alpine
LABEL       maintainer="christophe.frattino@elca.ch"
ARG         JAR_FILE=target/IdPTestClient.jar
COPY        ${JAR_FILE} app.jar
EXPOSE      7000
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]