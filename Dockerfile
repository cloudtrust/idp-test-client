FROM        docker-remote.artifactory.svc.elca.ch/maven:3.8.6-eclipse-temurin-11
LABEL       name="ephemeral/idp-test-client" releaseName="idp-test-client" repository="prj-cloudtrust-docker" releaseRepository="prj-cloudtrust-docker" maintainer="christophe.frattino@elca.ch"
ARG version=
ENV VERSION ${version}
COPY        pom.xml .
COPY        src src
RUN         mvn clean package
VOLUME      /tmp
EXPOSE      7000
ARG         JAR_FILE=target/IdPTestClient-${VERSION}.jar
COPY        ${JAR_FILE} app.jar
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]
