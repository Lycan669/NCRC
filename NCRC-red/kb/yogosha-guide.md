\# 📋 Guide Complet: Rédiger un Rapport Yogosha Gagnant



\## 🎯 Objectif

Rédiger des rapports \*\*CLAIRS, REPRODUCTIBLES, UTILES\*\* que les devs vont VOULOIR corriger.



\## 🔴 Les ERREURS à ÉVITER



\### ❌ ERREUR 1: Description Vague

MAUVAIS: "Il y a une faille XSS"

BON: "Injection XSS Stockée dans le champ 'Nom de profil' (PUT /api/profile) permettant l'exécution de JavaScript arbitraire dans le contexte de chaque utilisateur visitant ce profil"



\### ❌ ERREUR 2: Étapes Non Reproductibles

MAUVAIS: "Envoyer du SQL"

BON: "



GET /login

Entrer dans le champ email: admin' OR '1'='1' --

Cliquer 'Connexion'

Vérifier: vous êtes connecté en tant qu'admin sans connaître le mot de passe

"





\### ❌ ERREUR 3: Fix Générique

MAUVAIS: "Valider les inputs"

BON: "

Utiliser prepared statements (MySQLi):

$stmt = $pdo->prepare('SELECT \* FROM users WHERE email = ?');

&#x20;stmt−>execute(\[ email]);

"



\### ❌ ERREUR 4: POC Sans Contexte

MAUVAIS: Juste un payload XSS

BON: 



Payload: <img src=x onerror='fetch("/api/admin")'>

Où l'envoyer: Champ "bio" du profil

Résultat: Code exécuté chez chaque utilisateur visitant le profil





\---



\## ✅ TEMPLATE GAGNANT

\[TITRE]

\[Faille] - \[Où] - \[Impact]

EXEMPLE: Injection SQL dans formulaire de recherche utilisateurs



\[SÉVÉRITÉ]

🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low



\[DESCRIPTION - C'est LA PARTIE IMPORTANTE!]

Composant affecté: \[Quelle partie?]

Cause racine: \[Pourquoi ça existe?]

Impact direct: \[Que peut faire un attaquant?]

EXEMPLE:

"Le paramètre 'search' de GET /api/users n'échappe pas les single quotes, permettant une injection SQL complète. Un attaquant peut:



Bypasser le filtre de recherche

Accéder à TOUS les utilisateurs (même les admins)

Accéder aux password hashes

Modifier les données directement"





\[ÉTAPES REPRODUCTION - Doit être COPY-PASTE!]



Aller sur https://eduportal.local/search

Entrer dans 'Chercher utilisateur': admin' OR '1'='1' --

Cliquer "Rechercher"

✅ Résultat: 500+ utilisateurs au lieu de \~3



OU via API:

GET /api/search?q=admin' OR '1'='1' --

Réponse: 200 OK + tous les users (normalement 3 seulement)



\[POC - Preuve Authentique!]

Payload envoyé:



GET /api/users?search=admin' UNION SELECT id,email,password FROM admin --



Réponse serveur:

{

&#x20; "users": \[

&#x20;   {"id": 1, "name": "admin", "password": "e7cf3..."},

&#x20;   {"id": 2, "name": "user1", "password": "a2f5b..."}

&#x20; ]

}

Interprétation: Les passwords sont maintenant visibles! ⚠️



\[FIX PROPOSÉ - Doit être TECHNIQUE!]

Pour PHP/MySQLi:

// ❌ INSÉCURISÉ (actuellement)

$result = mysqli\_query($conn, "SELECT \* FROM users WHERE email = '$email'");



// ✅ SÉCURISÉ (prepared statement)

$stmt = $conn->prepare("SELECT \* FROM users WHERE email = ?");

$stmt->bind\_param("s", $email);

$stmt->execute();

$result = $stmt->get\_result();



\[IMPACT]

Sévérité: Critical

CVSS Score: 9.8

Impacts:



🔓 Accès non autorisé à TOUS les comptes utilisateurs

🔑 Vol des password hashes

💾 Modification/suppression de données

🚨 Non-conformité RGPD (données personnelles exposées)



Nombre d'utilisateurs affectés: TOUS (100%)



\---



\## 🏆 TIPS BONUS



1\. \*\*Sois SPÉCIFIQUE\*\*: Pas "XSS", mais "XSS stockée dans le champ bio du profil"

2\. \*\*Inclus TOUJOURS\*\*: Titre + Sévérité + Desc + Steps + POC + Fix + Impact

3\. \*\*POC = Preuve\*\*: Payload exact + Output exact (screenshot ou texte)

4\. \*\*Fix = Code\*\*: Pas juste théorie, montre le code JavaScript/PHP/Python

5\. \*\*Impact = $$\*\*: Explique pourquoi c'est grave pour l'entreprise

6\. \*\*Reproductibilité = 100%\*\*: Un dev doit pouvoir reproduire en 5 min



\---



\## 📊 Checklist Avant Soumission



\- \[ ] Titre clair (30 chars max)

\- \[ ] Sévérité appropriée

\- \[ ] Description technique et complète

\- \[ ] Étapes de reproduction testées (tu l'as vraiment fait?)

\- \[ ] POC authentique (payload exact + résultat exact)

\- \[ ] Fix technique (avec code)

\- \[ ] Impact business/data

\- \[ ] Pas d'infos personnelles (email, IP réelle, etc.)

\- \[ ] Format lisible (pas de mur de texte)



\---



\## 🎯 Scoring Yogosha (Estimation)



\- Trouver faille: ✅

\- Rapport complet: ✅✅

\- Fix proposé: ✅✅✅

\- \*\*TOTAL = 3 points par faille bien rapportée\*\*



\*\*Stratégie optimale pour Hack Ton Lycée:\*\*

\- Trouver 5-7 failles variées

\- Rédiger des rapports COMPLETS

\- Proposer des fixes



\*\*Total: 15-21 points possibles = Podium garanti! 🏆\*\*

