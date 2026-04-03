# Static Analysis Run Notes

Date: 2026-04-01
Project: WebGoatEnhanced

## Maven configuration change
- Added profile `spotbugs-security` in `pom.xml`.
- SpotBugs plugin: `com.github.spotbugs:spotbugs-maven-plugin:4.9.8.0`
- FindSecBugs plugin: `com.h3xstream.findsecbugs:findsecbugs-plugin:1.12.0`
- Execution phase/goals: `verify` with `spotbugs` and `check`
- Behavior: report-only (`failOnError=false`)

## Execution context
- Docker CLI is installed, but Docker daemon was unavailable (`/var/run/docker.sock` missing).
- Containerized scan execution was blocked in this session.
- Fallback used: local execution for the same analysis objectives.

## Commands executed
- SpotBugs + FindSecBugs:
  - `mvn -f /home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced/pom.xml -Pspotbugs-security -DskipTests com.github.spotbugs:spotbugs-maven-plugin:4.9.8.0:spotbugs`
- Semgrep security audit:
  - `semgrep --config=p/security-audit /home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced --json --output /home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced/audit-output/semgrep/semgrep_security_audit.json`
- Semgrep OWASP Top 10:
  - `semgrep --config=p/owasp-top-ten /home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced --json --output /home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced/audit-output/semgrep/semgrep_owasp_top10.json`

## Generated artifacts
- SpotBugs XML:
  - `audit-output/spotbugs/spotbugs.xml`
- Semgrep JSON reports:
  - `audit-output/semgrep/semgrep_security_audit.json`
  - `audit-output/semgrep/semgrep_owasp_top10.json`

## Quick counts
- SpotBugs BugInstance count: 256
- Semgrep p/security-audit findings: 38
- Semgrep p/owasp-top-ten findings: 20

## Notes
- SpotBugs completed with detector warnings from FindSecBugs SpringEntityLeakDetector parsing generic signatures, but Maven build ended with BUILD SUCCESS.
