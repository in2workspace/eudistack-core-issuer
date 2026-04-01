# ---------------------------------------------------------------------------
# Multi-stage build for the Issuer Core Backend
# ---------------------------------------------------------------------------

# --- Stage 1: build --------------------------------------------------------
FROM docker.io/gradle:9.4.1-jdk25 AS build
ARG SKIP_TESTS=false
WORKDIR /workspace
COPY build.gradle settings.gradle ./
COPY gradle ./gradle
COPY config ./config
COPY src ./src
RUN if [ "$SKIP_TESTS" = "true" ]; then \
      gradle build --no-daemon -x test -x checkstyleMain -x checkstyleTest; \
    else \
      gradle build --no-daemon; \
    fi

# --- Stage 2: runtime ------------------------------------------------------
FROM eclipse-temurin:25-jre-alpine
RUN addgroup -S nonroot && adduser -S nonroot -G nonroot

# ADOT Java Agent — activated via JAVA_TOOL_OPTIONS="-javaagent:/opt/aws-opentelemetry-agent.jar"
ARG ADOT_VERSION=2.11.2
ARG ADOT_SHA256=dfec7527f36526709e682922e51760b56f0a45775237d9d42c845b712eeeca23
ADD --chmod=444 \
    https://github.com/aws-observability/aws-otel-java-instrumentation/releases/download/v${ADOT_VERSION}/aws-opentelemetry-agent.jar \
    /opt/aws-opentelemetry-agent.jar
RUN echo "${ADOT_SHA256}  /opt/aws-opentelemetry-agent.jar" | sha256sum -c -

USER nonroot
WORKDIR /app
COPY --from=build /workspace/build/libs/*.jar /app/issuer.jar
ENTRYPOINT ["java", "-jar", "/app/issuer.jar"]
