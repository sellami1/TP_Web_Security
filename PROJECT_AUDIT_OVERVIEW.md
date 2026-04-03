# WebGoatEnhanced - Maven Project Overview

## 1) What this project is
WebGoatEnhanced is a Java/Spring Boot training platform based on OWASP WebGoat, intentionally built to demonstrate insecure patterns and security lessons in a controlled environment.

Primary learning goal:
- Teach web application vulnerabilities and exploitation techniques.

Important operational context:
- It is intentionally vulnerable.
- It should be run only in isolated lab/dev environments.

## 2) Maven project identity
From pom.xml:
- Group: org.owasp.webgoat
- Artifact: webgoat
- Version: 2025.4-SNAPSHOT
- Packaging: jar
- Parent: spring-boot-starter-parent 3.5.6
- Java target: 25

This is a single-module executable Spring Boot JAR project (not a Maven multi-module reactor).

## 3) High-level architecture
Entry point:
- Main class: org.owasp.webgoat.server.StartWebGoat

Runtime model:
- A parent Spring context is created first.
- Two servlet child applications are started from the same process:
  - WebWolf (helper side app for exercises)
  - WebGoat (main training app)

Default network exposure:
- WebGoat: 8080 with context /WebGoat
- WebWolf: 9090 with context /WebWolf

Default binding in properties:
- Host defaults to 127.0.0.1 in application properties.
- Docker entrypoint overrides server binding to 0.0.0.0 for container accessibility.

## 4) Main technology stack
Core framework and runtime:
- Spring Boot (Web, Security, Validation, Thymeleaf, Actuator, JPA)
- Flyway for DB migration
- HSQLDB as embedded/local database backend

Security and lesson-related libs:
- JSON/JWT tooling (jjwt, java-jwt, jose4j, jwks-rsa)
- OWASP-style educational vulnerable components used by lessons

Frontend/resource delivery:
- WebJars (Bootstrap, jQuery)
- Thymeleaf templates

Testing/tooling:
- Surefire (unit tests)
- Failsafe (integration tests)
- Playwright and Rest-Assured
- Spotless + Checkstyle
- Maven Enforcer rule blocks forbidden dependencies (for example log4j-core)

## 5) Build and execution flow
Typical local flow:
1. Build: ./mvnw clean install
2. Run: ./mvnw spring-boot:run

Packaged artifact:
- target/webgoat-<version>.jar

Spring Boot plugin configuration:
- Repackages to executable JAR.
- Main class explicitly set to StartWebGoat.
- Includes options to unpack specific libraries (asciidoctorj) at runtime.

## 6) Maven profiles worth knowing
Declared profiles include:
- local-server: placeholder profile id
- start-server (active by default):
  - Reserves random ports for test runs.
  - Starts the packaged JAR before integration tests.
  - Stops it after tests.
- owasp:
  - Runs dependency-check-maven.
  - Fails build for CVSS >= 7.
- coverage:
  - Enables JaCoCo reporting and checks.

## 7) Resource and configuration layout
Important resource files:
- src/main/resources/application-webgoat.properties
- src/main/resources/application-webwolf.properties

Behavior seen in properties:
- Context paths and ports are environment-driven.
- SSL can be toggled with environment variables.
- Actuator health and environment endpoints are enabled for lab usage.
- Error stacktrace is included (intentional for educational/debug context, unsafe for production).

## 8) Dockerfile explained
Base image:
- eclipse-temurin:25-jdk-noble
- JDK image is required because some lessons compile/execute Java code dynamically.

User and permissions:
- Creates non-root user webgoat.
- Adjusts group permissions for safer container runtime.
- Switches execution to user webgoat.

Artifact packaging into image:
- Copies built JAR from target/webgoat-*.jar to /home/webgoat/webgoat.jar.
- This means image build expects the project to be built first.

Ports:
- Exposes 8080 (WebGoat) and 9090 (WebWolf).

Environment:
- Sets default timezone TZ=Europe/Amsterdam (can be overridden at runtime).

Entrypoint:
- Launches Java with:
  - UTF-8 encoding.
  - user.home set to /home/webgoat.
  - multiple --add-opens flags for reflective access used by framework/lessons on modern JDK.
  - -Drunning.in.docker=true marker.
  - --server.address 0.0.0.0 so services are reachable through published container ports.

Healthcheck:
- Calls http://localhost:8080/WebGoat/actuator/health every 5s.
- Container is considered unhealthy if endpoint is not reachable.

Operational implication:
- This image is designed for lab/demo deployment, not hardened production use.

## 9) Security-relevant notes for your audit work
This project intentionally contains vulnerable lesson logic. During security assessment, separate:
- Intentional educational vulnerabilities (expected by design)
- Unintentional weaknesses in platform/runtime/configuration

Quick audit focus suggestions:
- Hardcoded defaults and secrets in config/env fallbacks
- Error handling verbosity and actuator exposure
- Third-party dependency risk and profile-based CVE gating
- Container hardening gaps (base image updates, dropped capabilities, runtime policy)

## 10) Short summary
WebGoatEnhanced is a single-JAR Spring Boot Maven project that starts two related web apps (WebGoat + WebWolf) for security training. The Dockerfile packages the built JAR into a non-root JDK container, exposes 8080/9090, binds to 0.0.0.0, and performs health checks through the actuator endpoint.
