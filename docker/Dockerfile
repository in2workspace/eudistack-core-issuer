# ---------------------------------------------------------------------------
# Multi-stage build for the Issuer Core Backend
# Context: must be the repo root  (docker build -f docker/Dockerfile ..)
# ---------------------------------------------------------------------------

# --- Stage 1: build --------------------------------------------------------
FROM docker.io/gradle:9.3.1-jdk25 AS build
ARG SKIP_TESTS=true
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
FROM eclipse-temurin:25-jdk-alpine
RUN addgroup -S nonroot && adduser -S nonroot -G nonroot
USER nonroot
WORKDIR /app
COPY --from=build /workspace/build/libs/*.jar /app/issuer.jar
ENTRYPOINT ["java", "-jar", "/app/issuer.jar"]
