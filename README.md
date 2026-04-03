# TP Web Security - Audit SAST (WebGoatEnhanced)

Ce depot contient les livrables de la Partie 1 du TP "Securisation d'une Application du SI" (Master DevOps), centre sur la detection de vulnerabilites via revue manuelle et outils SAST.

## Point d'entree recommande

Le fichier le plus important pour la correction est **REPONSES_WEBGOAT.md**.

- Il contient les reponses structurees a toutes les sections du TP.
- Il renvoie vers les preuves techniques et les artefacts produits.
- C'est le meilleur document pour une lecture rapide de la demarche et des conclusions.

## Objectif du depot

Documenter un audit de securite d'une application pedagogique volontairement vulnerable (WebGoatEnhanced), en separant:
- les vulnerabilites intentionnelles des lecons,
- les risques plateforme/configuration a corriger avant un usage cible.

## Contenu principal

- `.gitignore`: regles d'exclusion du depot.
- `PROJECT_AUDIT_OVERVIEW.md`: synthese technique Maven/architecture de WebGoatEnhanced.
- `REPONSES_WEBGOAT.md`: reponses detaillees aux questions du TP (document prioritaire).
- `TP_Securisation_Application_SI.md`: enonce complet du TP, objectifs, questions et livrables.
- `Vulnerabilities_Repport.md`: rapport final consolide de vulnerabilites (resume executif, tableau, details critiques, plan d'action).
- `audit-output/notes/static_analysis_run_notes.md`: notes d'execution des analyses.
- `audit-output/semgrep/custom-java-rules.yaml`: regles Semgrep personnalisees.
- `audit-output/semgrep/semgrep_custom_java_rules.json`: resultats Semgrep des regles personnalisees.
- `audit-output/semgrep/semgrep_owasp_top10.json`: resultats Semgrep OWASP Top 10.
- `audit-output/semgrep/semgrep_security_audit.json`: resultats Semgrep security-audit.
- `audit-output/spotbugs/spotbugs.xml`: rapport SpotBugs/FindSecBugs.
- `docs/index.html`: version web (dashboard) du rapport d'audit.

## Resultats cles (resume)

Source: rapport consolide (`Vulnerabilities_Repport.md`).

- Total findings bruts: 388
- Critiques: 56
- Hautes: 9
- Moyennes: 229
- Basses: 94
- Recommandation globale: conditionner le deploiement

## Outils utilises

- Revue manuelle (controle d'acces, config, gestion des erreurs, validation des entrees)
- SpotBugs + FindSecBugs (Java)
- Semgrep (rulesets security-audit + owasp-top-ten + regle Java personnalisee)
- Gitleaks (detection de secrets)
- OWASP Dependency-Check Maven (section dependances a consolider avec JSON)

## Arborescence

```text
TP_Web_Security/
├── .gitignore
├── PROJECT_AUDIT_OVERVIEW.md
├── README.md
├── REPONSES_WEBGOAT.md
├── TP_Securisation_Application_SI.md
├── Vulnerabilities_Repport.md
├── audit-output/
│   ├── notes/
│   │   └── static_analysis_run_notes.md
│   ├── semgrep/
│   │   ├── custom-java-rules.yaml
│   │   ├── semgrep_custom_java_rules.json
│   │   ├── semgrep_owasp_top10.json
│   │   └── semgrep_security_audit.json
│   └── spotbugs/
│       └── spotbugs.xml
└── docs/
    └── index.html
```

## Comment consulter les livrables

1. Commencer par `REPONSES_WEBGOAT.md` (fichier principal).
2. Lire le contexte pedagogique dans `TP_Securisation_Application_SI.md`.
3. Lire le rapport final dans `Vulnerabilities_Repport.md`.
4. Ouvrir la version web du rapport via `docs/index.html`.

## Reproduire les analyses (exemples de commandes)

Adapter les chemins selon votre environnement.

### SpotBugs + FindSecBugs

```bash
mvn -f /chemin/vers/WebGoatEnhanced/pom.xml -Pspotbugs-security -DskipTests \
  com.github.spotbugs:spotbugs-maven-plugin:4.9.8.0:spotbugs
```

### Semgrep (security-audit)

```bash
semgrep --config=p/security-audit /chemin/vers/WebGoatEnhanced \
  --json --output /chemin/vers/WebGoatEnhanced/audit-output/semgrep/semgrep_security_audit.json
```

### Semgrep (OWASP Top 10)

```bash
semgrep --config=p/owasp-top-ten /chemin/vers/WebGoatEnhanced \
  --json --output /chemin/vers/WebGoatEnhanced/audit-output/semgrep/semgrep_owasp_top10.json
```

### Semgrep (regles custom Java)

```bash
semgrep --config=/chemin/vers/WebGoatEnhanced/audit-output/semgrep/custom-java-rules.yaml \
  /chemin/vers/WebGoatEnhanced --json \
  --output /chemin/vers/WebGoatEnhanced/audit-output/semgrep/semgrep_custom_java_rules.json
```

### Gitleaks (Docker)

```bash
docker run --rm -v /chemin/vers/WebGoatEnhanced:/repo zricethezav/gitleaks:latest \
  detect --source /repo --report-format json --report-path /repo/gitleaks_report.json --verbose
```

### Dependency-Check (JSON recommande)

```bash
mvn -f /chemin/vers/WebGoatEnhanced/pom.xml -Powasp -DskipTests \
  org.owasp:dependency-check-maven:check \
  -Dformat=JSON -DoutputDirectory=/chemin/vers/WebGoatEnhanced/audit-output/dependency-check
```

## Limites et perimetre

- WebGoatEnhanced est volontairement vulnerable: certaines detections sont pedagogiques et non des regressions applicatives classiques.
- Les severites sont des findings bruts non dedoublonnes entre outils.
- La section dependances doit etre reconfirmee par un rapport JSON Dependency-Check recent.

## Actions prioritaires recommandees

- Remplacer NoOpPasswordEncoder par BCrypt/Argon2.
- Restreindre les endpoints actuator et desactiver les stacktraces en reponse.
- Corriger le flux upload contre le path traversal.
- Mettre un gate CI/CD bloquant sur HIGH/CRITICAL.

## Reference du projet cible

- Depot analyse: https://github.com/WebGoat/WebGoat

## Auteurs

Equipe DevOps M2
Date d'audit: 2026-04-02
