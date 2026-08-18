# The agent platform backend: Client Attester for device-resident agents.
#
# Two-stage so the runtime image carries no Maven and no source. The reactor is built from the repo
# root because device-enrolment depends on four sibling modules (oidf-jose, app-attest,
# device-instance, client-attestation) that are not published to a registry.
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml .
COPY libs libs
COPY servlets servlets
COPY plugins plugins
COPY services services
# The PF-dependent modules need jars that are not on Maven Central, so build only what this service
# needs. -am pulls in exactly the four libraries above.
RUN mvn -B -q -pl services/device-enrolment -am -DskipTests package

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /src/services/device-enrolment/target/device-enrolment-0.1.0.jar app.jar
COPY --from=build /src/services/device-enrolment/target/dependency ./lib

EXPOSE 8080
# APPLE_ALLOW_DEVELOPMENT is deliberately absent: development App Attest must be opted into per
# environment, never inherited from the image.
ENV PORT=8080
ENTRYPOINT ["java", "-cp", "app.jar:lib/*", "com.pingidentity.ps.oidf.enrolment.Main"]
