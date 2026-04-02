# TP — Sécurisation d'une Application du SI
### Master DevOps | Sécurité Applicative

---

**Durée estimée :** 4h  
**Niveau :** Master 2 DevOps  
**Prérequis :** Git, Docker, Python ou Node.js, notions de CI/CD  

---

## Contexte

Votre équipe DevOps vient de récupérer le code source d'une application web interne développée rapidement par une équipe externe. L'application est un API REST de gestion d'utilisateurs. Avant de l'intégrer dans le SI de production, vous êtes chargés d'en **auditer la sécurité**, de **détecter les vulnérabilités** et de **proposer des correctifs**.

Ce TP est découpé en plusieurs parties. La **Partie 1** porte sur la **détection des vulnérabilités dans le code** à l'aide d'outils d'analyse statique (SAST) et de revue manuelle.

---

## Partie 1 — Détection des Vulnérabilités dans le Code

### Objectifs pédagogiques

À l'issue de cette partie, vous serez capables de :

- Identifier les vulnérabilités courantes dans un code source (OWASP Top 10)
- Utiliser des outils d'analyse statique de sécurité (SAST)
- Détecter des secrets hardcodés dans un dépôt Git
- Analyser les dépendances tierces à la recherche de CVE connues
- Produire un rapport de vulnérabilités structuré

---

### 1.1 — Mise en place de l'environnement

#### 1.1.1 Récupération du projet cible

Clonez le dépôt de l'application vulnérable fournie par l'encadrant (ou utilisez l'application ci-dessous si non fournie) :

```bash
git clone https://github.com/WebGoat/WebGoat.git
cd WebGoat
```

> **Alternativement**, si vous travaillez avec une application Python/Flask volontairement vulnérable :
> ```bash
> git clone https://github.com/we45/Vulnerable-Flask-App.git
> cd Vulnerable-Flask-App
> ```

#### 1.1.2 Installation des outils d'analyse

Installez les outils suivants dans votre environnement (VM, conteneur Docker ou machine locale) :

```bash
# Bandit — Analyseur de sécurité pour Python
pip install bandit

# Semgrep — Outil SAST multilangage
pip install semgrep

# Gitleaks — Détection de secrets dans Git
# (télécharger le binaire depuis https://github.com/gitleaks/gitleaks/releases)
brew install gitleaks   # macOS
# ou via Docker :
docker pull zricethezav/gitleaks

# Safety — Vérification des dépendances Python
pip install safety

# npm audit (pour les projets Node.js — inclus nativement)
npm audit
```

> **Note :** Si vous travaillez avec une application Java (WebGoat), remplacez Bandit par **SpotBugs + Find Security Bugs** ou utilisez **Semgrep** qui est multilangage.

---

### 1.2 — Revue manuelle du code

Avant de lancer les outils automatisés, effectuez une **revue manuelle** du code source. Il s'agit d'une compétence essentielle que les outils ne remplacent pas entièrement.

#### 1.2.1 Points à inspecter manuellement

Parcourez les fichiers sources et répondez aux questions suivantes dans votre rapport :

**Authentification & Sessions**
- Les mots de passe sont-ils stockés en clair ou hashés ?
- Quel algorithme de hashage est utilisé ? Est-il considéré comme sûr (bcrypt, argon2 vs MD5, SHA1) ?
- Les tokens de session sont-ils générés de façon aléatoire et sécurisée ?
- Y a-t-il une gestion de l'expiration des sessions ?

**Entrées utilisateur**
- Les données reçues de l'utilisateur sont-elles validées et assainies avant utilisation ?
- Y a-t-il des constructions de requêtes SQL par concaténation de chaînes ?
- Les paramètres d'URL ou de formulaires sont-ils réutilisés directement dans des chemins de fichiers ?

**Configuration et secrets**
- Des clés API, mots de passe ou tokens sont-ils présents en clair dans le code ou les fichiers de config ?
- Le fichier `.gitignore` exclut-il correctement les fichiers `.env` et de configuration ?
- Les messages d'erreur renvoyés à l'utilisateur sont-ils trop verbeux (stack traces, noms de tables) ?

**Contrôle d'accès**
- Les routes protégées vérifient-elles bien l'authentification avant d'exécuter la logique métier ?
- Existe-t-il une vérification des droits (autorisation) en plus de l'authentification ?

#### 1.2.2 Exercice pratique

Examinez le fichier principal de l'application (ex. `app.py`, `server.js`, `MainController.java`). Identifiez et documentez **au minimum 3 problèmes de sécurité** en précisant pour chacun :

| Champ | Détail |
|---|---|
| Fichier & ligne | ex. `app.py:42` |
| Type de vulnérabilité | ex. SQL Injection, Hardcoded Secret |
| Référence OWASP | ex. A03:2021 – Injection |
| Description | Explication du problème |
| Impact potentiel | Ce qu'un attaquant peut faire |

---

### 1.3 — Analyse statique avec Bandit (Python)

Bandit analyse le code Python à la recherche de patterns de sécurité dangereux.

#### Lancer une analyse

```bash
# Analyse simple du projet
bandit -r ./app

# Avec rapport détaillé en format texte
bandit -r ./app -v

# Export au format JSON (utile pour l'intégration CI/CD)
bandit -r ./app -f json -o bandit_report.json

# Filtrer par sévérité (LOW, MEDIUM, HIGH)
bandit -r ./app -l  # uniquement HIGH severity
```

#### Comprendre les résultats

Bandit classe les issues selon deux axes : **Sévérité** (Low/Medium/High) et **Confiance** (Low/Medium/High).

Exemple de sortie :

```
>> Issue: [B106:hardcoded_password_funcarg] Possible hardcoded password: 'admin123'
   Severity: Low   Confidence: Medium
   Location: app/config.py:14
```

#### Questions — Bandit

1. Combien d'issues de sévérité **HIGH** avez-vous trouvées ? Listez-les.
2. Y a-t-il des faux positifs ? Si oui, comment le déterminez-vous ?
3. Quel est le code vulnérable identifié par la règle `B608` (SQL injection) ? Reproduisez-le et expliquez pourquoi il est dangereux.

---

### 1.4 — Analyse multilangage avec Semgrep

Semgrep est un outil SAST puissant qui s'appuie sur des règles communautaires et personnalisables.

#### Lancer une analyse

```bash
# Utiliser le ruleset de sécurité officiel
semgrep --config=p/security-audit ./

# Ruleset ciblé OWASP Top 10
semgrep --config=p/owasp-top-ten ./

# Ruleset pour Python ou Node.js
semgrep --config=p/python ./
semgrep --config=p/nodejs ./

# Export des résultats
semgrep --config=p/security-audit ./ --json > semgrep_report.json
```

#### Analyse d'une règle personnalisée

Créez un fichier `rules/custom.yaml` avec la règle suivante qui détecte l'utilisation de `eval()` :

```yaml
rules:
  - id: dangerous-eval
    patterns:
      - pattern: eval(...)
    message: "Utilisation dangereuse de eval() — risque d'injection de code"
    languages: [python, javascript]
    severity: ERROR
```

Lancez-la :

```bash
semgrep --config=rules/custom.yaml ./
```

#### Questions — Semgrep

1. Quelles vulnérabilités Semgrep détecte-t-il que Bandit n'a pas signalées ?
2. Créez une règle Semgrep personnalisée pour détecter l'utilisation de `MD5` ou `SHA1` dans le code. Documentez votre règle.
3. Quelle est la différence entre un outil SAST comme Semgrep et un outil DAST ? Dans quel cas utiliseriez-vous l'un ou l'autre ?

---

### 1.5 — Détection de secrets avec Gitleaks

Un des risques les plus fréquents est la présence de secrets (clés API, tokens, mots de passe) dans l'historique Git.

#### Scanner le dépôt

```bash
# Scanner tout l'historique Git
gitleaks detect --source . --verbose

# Scanner uniquement le répertoire de travail actuel (sans historique)
gitleaks detect --source . --no-git

# Via Docker
docker run -v $(pwd):/path zricethezav/gitleaks detect --source /path --verbose

# Export du rapport
gitleaks detect --source . --report-path gitleaks_report.json --report-format json
```

#### Simulation d'un secret dans l'historique

Pour comprendre comment un secret peut être exposé même après suppression, effectuez les commandes suivantes dans un dépôt de test :

```bash
mkdir test-repo && cd test-repo
git init

# Créer un fichier avec un faux secret
echo 'AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"' > config.py
git add config.py
git commit -m "Add config"

# "Supprimer" le secret et committer
echo 'AWS_SECRET_KEY = os.environ.get("AWS_SECRET_KEY")' > config.py
git add config.py
git commit -m "Fix: use env variable"

# Scanner l'historique
gitleaks detect --source . --verbose
```

**Observez** que Gitleaks détecte toujours le secret dans l'historique malgré sa suppression.

#### Questions — Gitleaks

1. Des secrets ont-ils été trouvés dans le dépôt analysé ? Lesquels (type, pas la valeur) ?
2. Comment aurait-on dû gérer ces secrets dès le départ ?
3. Quelle commande Git (avancée) permettrait de **réécrire l'historique** pour supprimer définitivement un secret ? Quels sont les risques de cette opération ?

---

### 1.6 — Audit des dépendances tierces

Les bibliothèques tierces peuvent elles-mêmes contenir des vulnérabilités connues (CVE).

#### Pour un projet Python

```bash
# Installer les dépendances
pip install -r requirements.txt

# Lancer l'audit
safety check

# Avec export
safety check --json > safety_report.json
```

#### Pour un projet Node.js

```bash
npm install
npm audit
npm audit --json > npm_audit_report.json

# Tentative de correction automatique
npm audit fix
```

#### Pour un projet Java (Maven)

```bash
mvn org.owasp:dependency-check-maven:check
```

#### Questions — Audit de dépendances

1. Listez les **3 CVE les plus critiques** (score CVSS le plus élevé) trouvées dans les dépendances.
2. Pour chacune, recherchez sur [https://nvd.nist.gov](https://nvd.nist.gov) la description officielle et expliquez le vecteur d'attaque en vos propres mots.
3. La commande `npm audit fix` ou `safety --auto-fix` résout-elle tous les problèmes ? Pourquoi certains ne peuvent-ils pas être corrigés automatiquement ?

---

### 1.7 — Consolidation : Rapport de vulnérabilités

À l'issue des étapes précédentes, vous devez produire un **rapport de vulnérabilités structuré**.

#### Format du rapport attendu

```
RAPPORT D'AUDIT DE SÉCURITÉ
Application : [Nom de l'application]
Date : [Date]
Auditeurs : [Noms]

1. RÉSUMÉ EXÉCUTIF
   - Nombre total de vulnérabilités : X
   - Critiques : X | Hautes : X | Moyennes : X | Basses : X
   - Recommandation générale : [Bloquer / Conditionner / Surveiller le déploiement]

2. TABLEAU DES VULNÉRABILITÉS

   ID | Outil | Fichier:Ligne | Type | OWASP | Sévérité | Impact | Statut
   ---|-------|---------------|------|-------|----------|--------|-------
   V01 | Bandit | app.py:42 | SQL Injection | A03 | HIGH | Accès BDD | À corriger
   ...

3. DÉTAIL DES VULNÉRABILITÉS CRITIQUES
   Pour chaque vulnérabilité HAUTE/CRITIQUE :
   - Description technique
   - Preuve (extrait de code)
   - Impact
   - Recommandation de correction

4. ANALYSE DES DÉPENDANCES
   - CVE identifiées
   - Versions vulnérables vs versions corrigées

5. SECRETS ET MAUVAISES CONFIGURATIONS
   - Secrets détectés (type, localisation)
   - Recommandations

6. CONCLUSION ET PLAN D'ACTION
   - Actions prioritaires (Quick Wins)
   - Actions à planifier
```

---

### 1.8 — Intégration dans un pipeline CI/CD (bonus)

Une fois les outils maîtrisés manuellement, l'objectif DevOps est de les **intégrer dans la chaîne CI/CD** pour que chaque commit soit automatiquement audité.

#### Exemple de configuration GitHub Actions

Créez le fichier `.github/workflows/security.yml` :

```yaml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  sast:
    name: Static Analysis (Bandit + Semgrep)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0  # Nécessaire pour Gitleaks (historique complet)

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install bandit safety semgrep

      - name: Run Bandit
        run: bandit -r ./app -f json -o bandit_report.json || true

      - name: Run Semgrep
        run: semgrep --config=p/security-audit ./ --json > semgrep_report.json || true

      - name: Run Safety
        run: safety check --json > safety_report.json || true

      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: security-reports
          path: |
            bandit_report.json
            semgrep_report.json
            safety_report.json
```

#### Questions — CI/CD (bonus)

1. Comment faire en sorte que le pipeline **bloque le merge** d'une PR si des vulnérabilités de sévérité HIGH sont détectées ?
2. Quelle est la différence entre un **fail hard** et un **fail soft** dans un pipeline de sécurité ? Quand privilégiez-vous l'un ou l'autre ?
3. Comment gérer les **faux positifs** récurrents sans désactiver les règles pour tout le projet ?

---

## Livrables de la Partie 1

À remettre avant la fin de la séance (ou dans le délai indiqué par l'encadrant) :

| Livrable | Format |
|---|---|
| Rapport de vulnérabilités | PDF ou Markdown |
| Fichiers de rapport bruts (`bandit_report.json`, `semgrep_report.json`, etc.) | JSON |
| Règle Semgrep personnalisée | YAML |
| Fichier `.github/workflows/security.yml` (bonus) | YAML |

---

## Ressources

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Semgrep Rules Registry](https://semgrep.dev/r)
- [Gitleaks GitHub](https://github.com/gitleaks/gitleaks)
- [NVD — National Vulnerability Database](https://nvd.nist.gov/)
- [CWE — Common Weakness Enumeration](https://cwe.mitre.org/)

---

*La Partie 2 abordera la correction des vulnérabilités et le durcissement de l'application.*