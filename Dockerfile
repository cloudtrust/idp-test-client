FROM        openjdk:8-jdk-alpine
LABEL       maintainer="christophe.frattino@elca.ch"
RUN         mvn clean package
VOLUME      /tmp
EXPOSE      7000
ARG         JAR_FILE=target/IdPTestClient.jar
COPY        ${JAR_FILE} app.jar
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]
