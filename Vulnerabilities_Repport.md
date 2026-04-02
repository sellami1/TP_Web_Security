# RAPPORT D'AUDIT DE SECURITE

Application : WebGoatEnhanced  
Date : 2026-04-02  
Auditeurs : Equipe DevOps M2

## 1. RESUME EXECUTIF

- Nombre total de vulnerabilites (findings bruts, non dedoublonnes): 388
- Critiques : 56 | Hautes : 9 | Moyennes : 229 | Basses : 94
- Recommandation generale : Conditionner le deploiement

Notes de comptage:
- SpotBugs/FindSecBugs: 256 findings (`priority=1`: 56, `priority=2`: 200)
- Semgrep (security-audit): 38 findings (`ERROR`: 9, `WARNING`: 29)
- Semgrep (OWASP Top 10): 20 findings (`ERROR`: 14, `WARNING`: 6) - utilise pour recoupement
- Gitleaks: 94 detections (44 `generic-api-key`, 42 `jwt`, 4 `aws-access-token`, 4 `private-key`)

Perimetre:
- Projet pedagogique volontairement vulnerable. Le tri distingue:
- Risques plateforme/configuration a corriger avant environnement cible
- Vulns intentionnelles de lesson a isoler/encadrer

## 2. TABLEAU DES VULNERABILITES

| ID | Outil | Fichier:Ligne | Type | OWASP | Severite | Impact | Statut |
|---|---|---|---|---|---|---|---|
| V01 | Revue manuelle | [WebGoatEnhanced/src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java#L87](./WebGoatEnhanced/src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java#L87) | NoOpPasswordEncoder (mot de passe non hache) | A02 | CRITICAL | Compromission de comptes si fuite DB | A corriger |
| V02 | Revue manuelle | [WebGoatEnhanced/src/main/java/org/owasp/webgoat/webwolf/WebSecurityConfig.java#L85](./WebGoatEnhanced/src/main/java/org/owasp/webgoat/webwolf/WebSecurityConfig.java#L85) | NoOpPasswordEncoder (mot de passe non hache) | A02 | CRITICAL | Reutilisation immediate des secrets compromis | A corriger |
| V03 | Revue manuelle | [WebGoatEnhanced/src/main/resources/application-webgoat.properties#L1](./WebGoatEnhanced/src/main/resources/application-webgoat.properties#L1) | Stacktrace toujours exposee | A05 | HIGH | Divulgation d'infos internes | A corriger |
| V04 | Revue manuelle | [WebGoatEnhanced/src/main/resources/application-webgoat.properties#L68](./WebGoatEnhanced/src/main/resources/application-webgoat.properties#L68) | Actuator env/health/configprops exposes | A05 | HIGH | Reconnaissance et fuite de configuration | A corriger |
| V05 | Revue manuelle | [WebGoatEnhanced/src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java#L43](./WebGoatEnhanced/src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java#L43) | `/actuator/**` en `permitAll` | A01/A05 | HIGH | Acces non authentifie a endpoints sensibles | A corriger |
| V06 | Revue manuelle | [WebGoatEnhanced/src/main/java/org/owasp/webgoat/container/users/UserService.java#L53](./WebGoatEnhanced/src/main/java/org/owasp/webgoat/container/users/UserService.java#L53) | SQL concatenee (`CREATE SCHEMA`) | A03 | HIGH | Injection SQL si contournement validation | A corriger |
| V07 | SpotBugs + Semgrep | [WebGoatEnhanced/src/main/java/org/owasp/webgoat/webwolf/FileServer.java#L75](./WebGoatEnhanced/src/main/java/org/owasp/webgoat/webwolf/FileServer.java#L75) | Path traversal via nom de fichier | A01 | HIGH | Ecriture/overwrite de fichiers | A corriger |
| V08 | Semgrep custom | [WebGoatEnhanced/src/main/java/org/dummy/insecure/framework/VulnerableTaskHolder.java#L67](./WebGoatEnhanced/src/main/java/org/dummy/insecure/framework/VulnerableTaskHolder.java#L67) | Command execution (`Runtime.exec`) | A03 | HIGH | RCE/commande systeme | Risque pedagogique a isoler |
| V09 | Semgrep custom | [WebGoatEnhanced/src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java#L39](./WebGoatEnhanced/src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java#L39) | Hash faible MD5 | A02 | MEDIUM | Collision/attaque hors usage pedagogique | Risque pedagogique |
| V10 | Gitleaks | [WebGoatEnhanced/src/main/java/org/owasp/webgoat/lessons/securitymisconfiguration/ActuatorExposureTask.java#L28](./WebGoatEnhanced/src/main/java/org/owasp/webgoat/lessons/securitymisconfiguration/ActuatorExposureTask.java#L28) | Secret hardcode (`generic-api-key`) | A02/A05 | MEDIUM | Fuite de credentiel si reutilise | Risque pedagogique |
| V11 | Gitleaks | [WebGoatEnhanced/src/main/resources/lessons/jwt/html/JWT.html#L322](./WebGoatEnhanced/src/main/resources/lessons/jwt/html/JWT.html#L322) | JWT en clair dans code | A07 | MEDIUM | Rejeu/abus de token dans mauvais contexte | Risque pedagogique |
| V12 | SpotBugs | [WebGoatEnhanced/src/main/java/org/owasp/webgoat/container/CurrentUsername.java](./WebGoatEnhanced/src/main/java/org/owasp/webgoat/container/CurrentUsername.java) | Pseudorandom predictable | A02 | MEDIUM | Token/prediction eventuelle | A verifier |

## 3. DETAIL DES VULNERABILITES CRITIQUES

### V01/V02 - NoOpPasswordEncoder (CRITICAL)

- Description technique:
  - Le provider de mots de passe utilise `NoOpPasswordEncoder`, donc pas de hash robuste.
- Preuve:

```java
@Bean
public NoOpPasswordEncoder passwordEncoder() {
  return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
}
```

- Localisations:
  - [WebGoatEnhanced/src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java#L87](./WebGoatEnhanced/src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java#L87)
  - [WebGoatEnhanced/src/main/java/org/owasp/webgoat/webwolf/WebSecurityConfig.java#L85](./WebGoatEnhanced/src/main/java/org/owasp/webgoat/webwolf/WebSecurityConfig.java#L85)
- Impact:
  - Exposition directe des mots de passe si dump base ou logs.
- Recommandation:
  - Remplacer par BCrypt/Argon2 (Spring Security `PasswordEncoderFactories` ou `BCryptPasswordEncoder`) et migrer les hashes.

### V03/V04/V05 - Mauvaise configuration d'erreurs et endpoints admin (HIGH)

- Description technique:
  - Stacktrace forcee en reponse (`include-stacktrace=always`).
  - Endpoints Actuator sensibles exposes.
  - Regle de securite autorise `/actuator/**` sans authentification.
- Preuves:
  - [WebGoatEnhanced/src/main/resources/application-webgoat.properties#L1](./WebGoatEnhanced/src/main/resources/application-webgoat.properties#L1)
  - [WebGoatEnhanced/src/main/resources/application-webgoat.properties#L68](./WebGoatEnhanced/src/main/resources/application-webgoat.properties#L68)
  - [WebGoatEnhanced/src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java#L43](./WebGoatEnhanced/src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java#L43)
- Impact:
  - Divulgation d'information de configuration et augmentation de la surface d'attaque.
- Recommandation:
  - `server.error.include-stacktrace=never`
  - Restreindre actuator: `management.endpoints.web.exposure.include=health,info`
  - Supprimer `permitAll` sur `/actuator/**` et proteger par role admin.

### V06 - SQL construit par concatenation (HIGH)

- Description technique:
  - Construction dynamique SQL avec `username`.
- Preuve:

```java
jdbcTemplate.execute("CREATE SCHEMA \"" + webGoatUser.getUsername() + "\" authorization dba");
```

- Localisation:
  - [WebGoatEnhanced/src/main/java/org/owasp/webgoat/container/users/UserService.java#L53](./WebGoatEnhanced/src/main/java/org/owasp/webgoat/container/users/UserService.java#L53)
- Impact:
  - Risque d'injection SQL si controle d'entree contourne.
- Recommandation:
  - Validation stricte whitelist (`^[a-zA-Z0-9_]{1,32}$`) avant usage SQL.
  - Eviter concatenation SQL dans DDL; encapsuler et echapper via API dediee.

### V07 - Risque de path traversal sur upload (HIGH)

- Description technique:
  - Le nom de fichier utilisateur est resolu sans normalisation/controle explicite.
- Preuve:

```java
var destinationFile = destinationDir.toPath().resolve(multipartFile.getOriginalFilename());
Files.copy(is, destinationFile);
```

- Localisation:
  - [WebGoatEnhanced/src/main/java/org/owasp/webgoat/webwolf/FileServer.java#L75](./WebGoatEnhanced/src/main/java/org/owasp/webgoat/webwolf/FileServer.java#L75)
- Impact:
  - Ecriture hors repertoire attendu selon payload/OS.
- Recommandation:
  - Normaliser (`normalize()`), verifier prefixe base dir, refuser `..`, separateurs et noms absolus.

## 4. ANALYSE DES DEPENDANCES

Observation:
- Aucun rapport JSON OWASP Dependency-Check n'est present dans `audit-output/dependency-check/`.
- Les CVE ci-dessous proviennent de la configuration de suppression:
  - [WebGoatEnhanced/config/dependency-check/project-suppression.xml](./WebGoatEnhanced/config/dependency-check/project-suppression.xml)

CVE identifiees (extraits les plus critiques a traiter/documenter):

| CVE | Composant | Version vulnerable observee | Version corrigee cible | Etat |
|---|---|---|---|---|
| CVE-2021-43859 | `com.thoughtworks.xstream:xstream` | `1.4.5` ([pom](./WebGoatEnhanced/pom.xml#L108)) | `>= 1.4.18` (recommande: version stable recente) | A corriger |
| CVE-2013-7285 | `com.thoughtworks.xstream:xstream` | `1.4.5` ([pom](./WebGoatEnhanced/pom.xml#L108)) | Version maintenue recente | A corriger |
| CVE-2022-22978 | `spring-boot-starter-security` (suppression historique) | `2.7.1` (note suppression) | `3.5.6` parent actuel ([pom](./WebGoatEnhanced/pom.xml#L8)) | Deja mitige (a verifier par scan)|

Action attendue pour fiabiliser la section dependances:
- Executer `mvn org.owasp:dependency-check-maven:check -Dformat=JSON -DoutputDirectory=audit-output/dependency-check`
- Conserver le top 3 CVE par CVSS depuis le JSON genere.

## 5. SECRETS ET MAUVAISES CONFIGURATIONS

Secrets detectes (Gitleaks):
- 94 detections au total:
- `generic-api-key`: 44
- `jwt`: 42
- `aws-access-token`: 4
- `private-key`: 4

Localisations exemple:
- [WebGoatEnhanced/src/main/java/org/owasp/webgoat/lessons/securitymisconfiguration/ActuatorExposureTask.java#L28](./WebGoatEnhanced/src/main/java/org/owasp/webgoat/lessons/securitymisconfiguration/ActuatorExposureTask.java#L28)
- [WebGoatEnhanced/src/main/resources/lessons/jwt/html/JWT.html#L322](./WebGoatEnhanced/src/main/resources/lessons/jwt/html/JWT.html#L322)

Mauvaises configurations notables:
- Stacktrace exposee: [WebGoatEnhanced/src/main/resources/application-webgoat.properties#L1](./WebGoatEnhanced/src/main/resources/application-webgoat.properties#L1)
- Exposition actuator: [WebGoatEnhanced/src/main/resources/application-webgoat.properties#L68](./WebGoatEnhanced/src/main/resources/application-webgoat.properties#L68)
- Secret OAuth fallback `dummy`:
  - [WebGoatEnhanced/src/main/resources/application-webgoat.properties#L71](./WebGoatEnhanced/src/main/resources/application-webgoat.properties#L71)
  - [WebGoatEnhanced/src/main/resources/application-webwolf.properties#L54](./WebGoatEnhanced/src/main/resources/application-webwolf.properties#L54)

Recommandations:
- Isoler strictement les lecons vulnerables du socle runtime de demonstration.
- Basculer tous les secrets vers variables d'environnement/secret manager.
- Ajouter une politique de pre-commit + CI (Gitleaks + Semgrep) avec blocage sur severite HIGH/CRITICAL.

## 6. CONCLUSION ET PLAN D'ACTION

Actions prioritaires (Quick Wins - 1 a 3 jours):
1. Remplacer `NoOpPasswordEncoder` par BCrypt/Argon2.
2. Fermer l'exposition `/actuator/**` et desactiver stacktraces en reponse.
3. Corriger l'upload pour neutraliser le path traversal.
4. Ajouter un gate CI/CD bloquant sur severite HIGH/CRITICAL.

Actions a planifier (1 a 3 semaines):
1. Mettre a jour `xstream` (actuellement `1.4.5`) et relancer un scan Dependency-Check complet.
2. Separer code pedagogique vuln des composants plateforme deployables.
3. Mettre en place un registre de faux positifs documente (expiration + justification).
4. Ajouter des tests de securite automatiques (SAST + integration tests de controle d'acces).

---

## Annexes - Sources d'audit exploitees

- [WebGoatEnhanced/audit-output/spotbugs/spotbugs.xml](./WebGoatEnhanced/audit-output/spotbugs/spotbugs.xml)
- [WebGoatEnhanced/audit-output/semgrep/semgrep_security_audit.json](./WebGoatEnhanced/audit-output/semgrep/semgrep_security_audit.json)
- [WebGoatEnhanced/audit-output/semgrep/semgrep_owasp_top10.json](./WebGoatEnhanced/audit-output/semgrep/semgrep_owasp_top10.json)
- [WebGoatEnhanced/audit-output/semgrep/semgrep_custom_java_rules.json](./WebGoatEnhanced/audit-output/semgrep/semgrep_custom_java_rules.json)
- [WebGoatEnhanced/gitleaks_report.json](./WebGoatEnhanced/gitleaks_report.json)
- [WebGoatEnhanced/config/dependency-check/project-suppression.xml](./WebGoatEnhanced/config/dependency-check/project-suppression.xml)
- [REPONSES_WEBGOAT.md](./REPONSES_WEBGOAT.md)
- [TP_Securisation_Application_SI.md](./TP_Securisation_Application_SI.md)
