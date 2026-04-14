FROM r-docker-registry-1-docker-io.artifactory.svc.elca.ch/eclipse-temurin:11.0.30_7-jre-noble

LABEL name="ephemeral/idp-test-client" releaseName="idp-test-client" repository="prj-cloudtrust-docker" releaseRepository="prj-cloudtrust-docker"
ARG version=
ENV VERSION ${version}

ENV LANG en_US.UTF-8
ENV TZ=Europe/Zurich

COPY target/IdPTestClient-${VERSION}.jar /opt/IdPTestClient.jar

RUN echo "idp-test-client:x:0:root" >> /etc/group && \
    echo "idp-test-client:x:1000:0:idp-test-client user::/sbin/nologin" >> /etc/passwd

USER 1000

# For generated samlSPMetadata.xml
WORKDIR /tmp

CMD ["java", "-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005", "-jar", "/opt/IdPTestClient.jar"]
EXPOSE 7000
EXPOSE 5005
