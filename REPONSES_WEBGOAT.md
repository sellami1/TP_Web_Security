<!-- Include TP_Securisation_Application_SI.md -->
# Reponses au [TP_Securisation_Application_SI.md](TP_Securisation_Application_SI.md)

Contexte:
- WebGoatEnhanced est un projet pedagogique volontairement vulnerable.
- Les constats ci-dessous distinguent ce qui est intentionnel (lessons) de ce qui serait critique en production.

# 1.2.1 - Points à inspecter manuellement

1. Les mots de passe sont-ils stockes en clair ou hashes ?
- Constat: mots de passe geres en clair cote authentification applicative.
- Preuves:
  - src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java:87-88 (NoOpPasswordEncoder)
  - src/main/java/org/owasp/webgoat/webwolf/WebSecurityConfig.java:85-86 (NoOpPasswordEncoder)
  - src/main/java/org/owasp/webgoat/container/users/WebGoatUser.java:23 (champ password)
  - src/main/java/org/owasp/webgoat/webwolf/user/WebWolfUser.java:22 (champ password)
  - src/main/resources/db/container/V1__init.sql:47 (colonne password)

2. Quel algorithme de hashage est utilise ?
- Constat: aucun hash de mot de passe dans ce flux (NoOpPasswordEncoder).
- Evaluation: non securise pour un contexte production.

3. Les tokens de session sont-ils generes de facon aleatoire et securisee ?
- Constat: pas de generation custom visible dans le code metier principal; gestion deleguee au framework/session HTTP.
- Indices:
  - src/main/resources/application-webgoat.properties:4
  - src/main/resources/application-webwolf.properties:13

4. Y a-t-il une gestion de l'expiration des sessions ?
- Constat:
  - WebWolf: timeout explicite defini.
  - WebGoat: pas de timeout explicite dans ce fichier de config (comportement serveur par defaut).
- Preuves:
  - src/main/resources/application-webwolf.properties:14
  - src/main/resources/application-webgoat.properties:4

## Entrees utilisateur

5. Les donnees utilisateur sont-elles validees et assainies avant utilisation ?
- Constat: validation partielle seulement.
- Validation presente:
  - src/main/java/org/owasp/webgoat/container/users/UserForm.java (taille/pattern)
  - src/main/java/org/owasp/webgoat/container/users/UserValidator.java
- Zones a risque:
  - src/main/java/org/owasp/webgoat/webwolf/FileServer.java:75 (nom de fichier utilisateur dans path de destination)

6. Y a-t-il des requetes SQL par concatenation ?
- Constat: oui.
- Intentionnel (lessons): nombreux exemples SQLi pedagogiques.
  - Exemple: src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson10.java:49
- Plateforme/socle (a surveiller):
  - src/main/java/org/owasp/webgoat/container/users/UserService.java:53 (CREATE SCHEMA avec username concatene)
  - src/main/java/org/owasp/webgoat/container/lessons/LessonConnectionInvocationHandler.java:31 (SET SCHEMA concatene)

7. Parametres URL/formulaires reutilises dans des chemins de fichiers ?
- Constat: oui, notamment via upload/nom de fichier.
- Preuves:
  - src/main/java/org/owasp/webgoat/webwolf/FileServer.java:75
  - src/main/java/org/owasp/webgoat/webwolf/MvcConfiguration.java:23

## Configuration et secrets

8. Secrets en clair dans code/config ?
- Constat: pas de secret reel evident dans cet echantillon, mais plusieurs valeurs faibles par defaut.
- Exemples:
  - src/main/resources/application-webgoat.properties:14 (mot de passe keystore par defaut "password")
  - src/main/resources/application-webgoat.properties:71 (client secret OAuth fallback "dummy")
  - src/main/resources/application-webwolf.properties:54 (client secret OAuth fallback "dummy")

9. Le .gitignore exclut-il correctement .env et configs sensibles ?
- Constat: pas de regle explicite .env observee.
- Preuve: .gitignore

10. Les messages d'erreur sont-ils trop verbeux ?
- Constat: oui, stacktraces activees et endpoints actuator sensibles exposes.
- Preuves:
  - src/main/resources/application-webgoat.properties:1 (include-stacktrace=always)
  - src/main/resources/application-webwolf.properties:1 (include-stacktrace=always)
  - src/main/resources/application-webgoat.properties:67 (health details always)
  - src/main/resources/application-webgoat.properties:68 (exposition env, health, configprops)

## Controle d'acces

11. Les routes protegees verifient-elles l'authentification ?
- Constat: globalement oui via anyRequest().authenticated(), avec exceptions permitAll larges.
- Preuves:
  - src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java:46
  - src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java:43 (/actuator/** en permitAll)
  - src/main/java/org/owasp/webgoat/webwolf/WebSecurityConfig.java:45
  - src/main/java/org/owasp/webgoat/webwolf/WebSecurityConfig.java:44 (POST /files, /mail, /requests en permitAll)

12. Y a-t-il une verification des droits (autorisation) en plus de l'authentification ?
- Constat: faible au niveau global; peu de controle fin par role dans les regles HTTP globales.
- Preuves:
  - src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java
  - src/main/java/org/owasp/webgoat/webwolf/WebSecurityConfig.java

# 1.2.2 - Exercice pratique

| Fichier & ligne | Type de vulnerabilite | Reference OWASP | Description | Impact potentiel |
|---|---|---|---|---|
| src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java:87 et src/main/java/org/owasp/webgoat/webwolf/WebSecurityConfig.java:85 | Cryptographie insuffisante (NoOpPasswordEncoder) | A02:2021 - Cryptographic Failures | L'encodeur NoOp implique l'absence de hashage robuste des mots de passe. | Si la base est compromise, les mots de passe sont directement reutilisables pour prise de compte. |
| src/main/resources/application-webgoat.properties:1 et src/main/resources/application-webwolf.properties:1 | Divulgation d'informations sensibles via erreurs | A05:2021 - Security Misconfiguration | server.error.include-stacktrace=always expose des details internes en reponse d'erreur. | Facilite la reconnaissance d'attaque (classes, chemins, composants) et l'enchainement d'exploits. |
| src/main/resources/application-webgoat.properties:68 et src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java:43 | Exposition excessive des endpoints d'administration | A05:2021 - Security Misconfiguration | Les endpoints actuator sensibles (env, health, configprops) sont exposes et /actuator/** est en permitAll. | Un attaquant peut collecter des informations de configuration et faciliter un pivot vers d'autres composants. |
| src/main/java/org/owasp/webgoat/container/users/UserService.java:53 | Injection SQL par concatenation | A03:2021 - Injection | La commande SQL CREATE SCHEMA est construite avec concatenation du username. | Si les contraintes d'entree sont contournees, risque d'altération SQL ou d'isolement inter-utilisateurs defaillant. |
| src/main/java/org/owasp/webgoat/webwolf/FileServer.java:75 | Reutilisation d'entree utilisateur dans un chemin de fichier | A01:2021 - Broken Access Control (risque Path Traversal) | Le nom de fichier fourni par l'utilisateur est resolu dans le chemin de destination sans normalisation stricte visible. | Ecriture/ecrasement de fichiers inattendus selon les protections effectivement appliquees au runtime. |

# 1.3 - Analyse statique avec "SpotBugs" & "FindSecBugs" (Java)

## Lancement des analyses

Contexte d'execution:
- Le profil Maven `spotbugs-security` a ete ajoute dans `pom.xml` avec:
  - SpotBugs: `com.github.spotbugs:spotbugs-maven-plugin:4.9.8.0`
  - FindSecBugs: `com.h3xstream.findsecbugs:findsecbugs-plugin:1.12.0`

Commande executee avec succes pour produire le rapport:
- `mvn -f /home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced/pom.xml -Pspotbugs-security -DskipTests com.github.spotbugs:spotbugs-maven-plugin:4.9.8.0:spotbugs`

Resultat produit:
- Rapport XML genere: `target/spotbugsXml.xml`
- Rapport archive pour le TP: `audit-output/spotbugs/spotbugs.xml`

Remarque importante:
- FindSecBugs n'est pas lance par une commande separee: il est charge comme plugin SpotBugs pendant la meme execution.

## Compréhension des résultats

Difference d'usage:
- SpotBugs:
  - Moteur principal d'analyse statique bytecode Java.
  - Detecte surtout des patterns generiques (bug patterns qualite, fiabilite, mauvaises pratiques, certains signaux securite).
- FindSecBugs:
  - Extension specialisee securite pour SpotBugs.
  - Ajoute des regles OWASP/CWE (injection, deserialisation, crypto faible, CSRF, path traversal, etc.).

Difference de sortie:
- Sortie unique du run: un seul rapport SpotBugs (XML/HTML selon config), qui contient a la fois:
  - les findings SpotBugs "core"
  - les findings ajoutes par FindSecBugs
- Dans `spotbugs.xml`, les findings de securite issus de l'extension apparaissent avec des types comme:
  - `SQL_INJECTION_JDBC`
  - `SPRING_CSRF_PROTECTION_DISABLED`
  - `PATH_TRAVERSAL_IN`

Quand utiliser quoi:
- SpotBugs seul:
  - quand l'objectif principal est la qualite/fiabilite du code Java.
  - utile en baseline sur tous les projets Java.
- SpotBugs + FindSecBugs (recommande pour audit securite):
  - quand on veut une analyse orientee vulnerabilites applicatives.
  - adapte a un TP securite, a une revue secure coding, et a un controle CI securite.

Limites pratiques a garder en tete:
- Faux positifs possibles (surtout sur projet pedagogique volontairement vulnerable).
- Certaines detections sont "intentionnelles" dans WebGoat et doivent etre etiquetees comme telles dans le rapport final.

## Questions

1. Combien d'issues de severite HIGH avez-vous trouvees ? Listez-les.
- Avec SpotBugs/FindSecBugs, l'equivalent de "HIGH" est plutot `priority='1'` (plus critique).
- Resume global du rapport:
  - `priority_1='56'` (toutes categories)
  - `total_bugs='256'`
- Si on filtre sur la securite (`category='SECURITY'` + `priority='1'`), on obtient 32 occurrences.
- Exemples de types critiques detectes:
  - `SPRING_CSRF_PROTECTION_DISABLED`
  - `SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING`
  - `SQL_INJECTION_JDBC`
  - `OBJECT_DESERIALIZATION`
  - `PATH_TRAVERSAL_IN`
  - `WEAK_MESSAGE_DIGEST_MD5`
  - `URLCONNECTION_SSRF_FD`

2. Y a-t-il des faux positifs ? Si oui, comment le determinez-vous ?
- Oui, il y a des faux positifs potentiels, et dans WebGoat il y a aussi des vulnerabilites volontaires (contexte pedagogique).
- Methode de tri/validation:
  - verifier si l'entree est reellement controlable par un attaquant;
  - verifier si le chemin de code est atteignable en execution reelle;
  - verifier le contexte (code lesson/test intentionnel vs socle plateforme);
  - recouper avec revue manuelle et un autre outil (ex: Semgrep) avant priorisation finale.

3. Quel est le code vulnerable identifie par la regle `B608` (SQL injection) ? Reproduisez-le et expliquez pourquoi il est dangereux.
- En Java avec SpotBugs/FindSecBugs, l'equivalent de `B608` est `SQL_INJECTION_JDBC`.
- Exemple detecte dans le projet:

```java
statement.execute("SET SCHEMA \"" + user.getUsername() + "\"");
```

- Pourquoi c'est dangereux:
  - la commande SQL est construite par concatenation de chaine avec une valeur dynamique;
  - si la valeur est influencee (directement ou indirectement), elle peut alterer la requete executee;
  - impact possible: injection SQL, changement de schema non prevu, contournement de l'isolation logique.


# 1.4 - Analyse multilangage avec Semgrep

## Lancement des analyses

Commandes executees avec succes:
- `semgrep --config=p/security-audit /home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced --json --output /home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced/audit-output/semgrep/semgrep_security_audit.json`
- `semgrep --config=p/owasp-top-ten /home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced --json --output /home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced/audit-output/semgrep/semgrep_owasp_top10.json`

Resume des sorties:
- Run `p/security-audit`:
  - 1006 fichiers scannes (git-tracked)
  - 83 regles executees
  - 38 findings detectes
- Run `p/owasp-top-ten`:
  - 1007 fichiers scannes (git-tracked)
  - 160 regles executees
  - 20 findings detectes

Artefacts generes:
- `audit-output/semgrep/semgrep_security_audit.json`
- `audit-output/semgrep/semgrep_owasp_top10.json`


## Analyse d'une règle personnalisée

Regle personnalisee adaptee au projet Java/Maven (fichier cree):
- `audit-output/semgrep/custom-java-rules.yaml`

Code de la regle:

```yaml
rules:
  - id: java-dangerous-runtime-exec
    patterns:
      - pattern: Runtime.getRuntime().exec(...)
    message: "Utilisation dangereuse de Runtime.exec() - risque de Command Injection"
    languages: [java]
    severity: ERROR

  - id: java-weak-hash-md5-sha1
    patterns:
      - pattern-either:
          - pattern: MessageDigest.getInstance("MD5")
          - pattern: MessageDigest.getInstance("SHA1")
          - pattern: MessageDigest.getInstance("SHA-1")
    message: "Algorithme de hash faible detecte (MD5/SHA1) - preferer SHA-256/SHA-512 + salt"
    languages: [java]
    severity: WARNING
```

Commande executee:
- `semgrep --config=/home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced/audit-output/semgrep/custom-java-rules.yaml /home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced --json --output /home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced/audit-output/semgrep/semgrep_custom_java_rules.json`

Resume de sortie (run personnalise):
- 314 fichiers Java cibles
- 2 regles executees
- 2 findings detectes
- Exemples:
  - `java-dangerous-runtime-exec` sur `src/main/java/org/dummy/insecure/framework/VulnerableTaskHolder.java:67`
  - `java-weak-hash-md5-sha1` sur `src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java:39`

Artefact genere:
- `audit-output/semgrep/semgrep_custom_java_rules.json`

Difference avec les runs non personnalises:
- Non personnalise (`p/security-audit`, `p/owasp-top-ten`):
  - large couverture multiregles
  - plus de bruit mais meilleure detection generale
  - resultats observes ici: 38 findings puis 20 findings
- Personnalise (`custom-java-rules.yaml`):
  - couverture ciblee sur des patterns precis du contexte Java
  - moins de bruit, verification rapide d'hypotheses/metiers
  - resultat ici: 2 findings tres focalises

## Questions

1. Quelles vulnerabilites Semgrep detecte-t-il que Bandit n'a pas signalees ?
- Dans ce contexte Java, Bandit n'est pas adapte (outil Python), alors que Semgrep detecte bien des problemes sur le code Java et la configuration.
- Exemples detectes par Semgrep dans ce projet:
  - SQL Injection (formatted SQL string)
  - Path Traversal
  - Open Redirect
  - Deserialization d'objets non fiables
  - Cookies sans attributs de securite (HttpOnly/Secure)
  - Weak crypto (MD5, random non cryptographique)
  - Mappings Spring non restreints (risque CSRF)

2. Creez une regle Semgrep personnalisee pour detecter l'utilisation de `MD5` ou `SHA1` dans le code. Documentez votre regle.
- Regle creee et utilisee dans le fichier `audit-output/semgrep/custom-java-rules.yaml`.
- Extrait pertinent (rule hash faible):

```yaml
- id: java-weak-hash-md5-sha1
  patterns:
    - pattern-either:
        - pattern: MessageDigest.getInstance("MD5")
        - pattern: MessageDigest.getInstance("SHA1")
        - pattern: MessageDigest.getInstance("SHA-1")
  message: "Algorithme de hash faible detecte (MD5/SHA1) - preferer SHA-256/SHA-512 + salt"
  languages: [java]
  severity: WARNING
```

- Resultat observe sur ce projet:
  - 1 finding pour cette regle (sur `HashingAssignment.java:39`), dans le rapport `audit-output/semgrep/semgrep_custom_java_rules.json`.


# 1.5 - Detection de secrets avec Gitleaks

## Lancement

Commandes executees avec succes sur WebGoatEnhanced:

```bash
docker run --rm -v /home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced:/repo zricethezav/gitleaks:latest detect --source /repo --verbose
```
```bash
docker run --rm -v /home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced:/repo zricethezav/gitleaks:latest detect --source /repo --report-format json --report-path /repo/gitleaks_report.json --verbose
```

## Questions

1. Des secrets ont-ils ete trouves dans le depot analyse ? Lesquels (type, pas la valeur) ?
- Oui.
- Types identifies dans le rapport:
  - JWT
  - generic API key
  - private key
  - AWS access token
- Synthese du rapport:
  - generic-api-key: 44 alertes
  - jwt: 42 alertes
  - private-key: 4 alertes
  - aws-access-token: 4 alertes

2. Comment aurait-on du gerer ces secrets des le depart ?
- Ne jamais hardcoder de secrets dans le code, les tests ou les ressources HTML.
- Utiliser des variables d'environnement, un vault ou un secret manager pour les valeurs sensibles.
- Charger les secrets uniquement au runtime, avec des valeurs de test distinctes pour l'environnement pedagogique.
- Ajouter des regles de secret scanning dans la CI et faire echouer le pipeline sur les secrets reels.
- Des qu'un secret est expose, le revoquer et le rotationner au lieu de simplement le supprimer du code.

3. Quelle commande Git avancee permettrait de re-ecrire l'historique pour supprimer definitivement un secret ? Quels sont les risques de cette operation ?
- Commande recommandee: git filter-repo.
- Exemple: git filter-repo --path chemin/du/fichier --invert-paths ou un remplacement cible pour supprimer la valeur sensible.
- Risques:
  - reecriture complete de l'historique Git;
  - necessite souvent un force push;
  - casse les clones locaux, branches partagees et references de pull request;
  - exige une coordination stricte avec toute l'equipe.

# 1.6 - Audit des dépendances tierces

## Lancement

Commande d'analyse utilisée pour le projet:

```bash
mvn -f /home/kadhem/devops-m1/M-Soufiene/sec-audit/WebGoatEnhanced/pom.xml -Powasp -DskipTests org.owasp:dependency-check-maven:check
```

## Questions

1. Listez les 3 CVE les plus critiques (score CVSS le plus élevé) trouvées dans les dépendances.
- Le profil `owasp` du `pom.xml` exécute `dependency-check-maven` avec le fichier de suppression `config/dependency-check/project-suppression.xml`.
- Les trois CVE les plus critiques retenues pour cette base sont:
  - CVE-2022-22978 - Spring Security - 9.8 CRITICAL
  - CVE-2021-21341 - XStream - 7.5 HIGH
  - CVE-2021-43859 - XStream - 7.5 HIGH

2. Pour chacune, recherchez sur https://nvd.nist.gov la description officielle et expliquez le vecteur d'attaque en vos propres mots.
- CVE-2022-22978:
  - Description NVD: `RegexRequestMatcher` pouvait être contourné sur certains conteneurs servlet lorsque l'expression régulière contenait un point `.`; cela permettait un contournement d'autorisation.
  - Vecteur d'attaque: un attaquant envoie une requête spécialement construite pour passer une règle d'accès mal définie et atteindre une route qui devait être protégée.
- CVE-2021-21341:
  - Description NVD: XStream avant 1.4.16 pouvait permettre à un attaquant distant de monopoliser 100% du CPU via un flux d'entrée manipulé, provoquant un déni de service.
  - Vecteur d'attaque: l'attaquant soumet un XML piégé à l'endpoint qui désérialise l'entrée; le traitement consomme excessivement les ressources et bloque le service.
- CVE-2021-43859:
  - Description NVD: XStream avant 1.4.19 pouvait aussi permettre une consommation CPU excessive via un flux d'entrée malformé, entraînant un déni de service.
  - Vecteur d'attaque: une entrée XML spécialement forgée déclenche un calcul coûteux pendant la désérialisation et épuise les ressources de la JVM.

3. La commande `npm audit fix` ou `safety --auto-fix` résout-elle tous les problèmes ? Pourquoi certains ne peuvent-ils pas être corrigés automatiquement ?
- Non.
- Ces outils ne corrigent automatiquement que les dépendances pour lesquelles une version compatible et sûre existe sans casser l'arbre de dépendances.
- Certains problèmes ne sont pas corrigés automatiquement quand:
  - la mise à jour impose un changement majeur de version;
  - aucune version corrigée compatible n'existe dans la chaîne de dépendances;
  - la faille provient d'un composant transitive verrouillé par un autre package;
  - la correction demanderait une refonte du code applicatif et pas seulement une mise à jour de paquet.