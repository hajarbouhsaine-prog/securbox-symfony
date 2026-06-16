# 🔐 SecurBox — Guide de déploiement Docker

## Prérequis

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installé
- [Git](https://git-scm.com/) installé

---

## 🚀 Démarrage rapide (5 étapes)

### Étape 1 — Cloner le projet

```bash
git clone https://github.com/TON_USERNAME/securbox.git
cd securbox
```

### Étape 2 — Configurer les variables d'environnement

```bash
# Copier le fichier template
cp .env.docker .env
```

Puis ouvrir `.env` et remplacer les valeurs `CHANGE_MOI_*` :

| Variable | Description | Exemple |
|----------|-------------|---------|
| `APP_SECRET` | Clé secrète Symfony (32 car.) | `a1b2c3d4e5f6...` |
| `DB_PASSWORD` | Mot de passe base de données | `MonMotDePasse123!` |
| `DB_ROOT_PASSWORD` | Mot de passe root MySQL | `RootPass456!` |
| `SODIUM_ENCRYPTION_KEY` | Clé de chiffrement (voir ci-dessous) | `base64:...` |

**Générer la clé Sodium** (après l'étape 3) :
```bash
docker compose exec app php -r "echo base64_encode(sodium_crypto_aead_xchacha20poly1305_ietf_keygen());"
```

### Étape 3 — Construire et lancer

```bash
docker compose up -d --build
```

*La première fois, ça prend 3-5 minutes (téléchargement des images).*

### Étape 4 — Initialiser la base de données

```bash
# Créer les tables via les migrations Doctrine
docker compose exec app php bin/console doctrine:migrations:migrate --no-interaction
```

### Étape 5 — Accéder à l'application

| Service | URL |
|---------|-----|
| 🌐 SecurBox | http://localhost:8080 |
| 🗃️ phpMyAdmin | http://localhost:8081 |

---

## 📋 Commandes utiles

```bash
# Voir l'état des conteneurs
docker compose ps

# Voir les logs en temps réel
docker compose logs -f

# Ouvrir un terminal PHP
docker compose exec app bash

# Vider le cache Symfony
docker compose exec app php bin/console cache:clear

# Arrêter les conteneurs
docker compose down

# Arrêter ET supprimer les données (⚠️)
docker compose down -v
```

---

## 🏗️ Architecture

```
securbox/
├── docker/
│   ├── nginx/
│   │   └── nginx.conf       # Config serveur web
│   ├── php/
│   │   └── php.ini          # Config PHP
│   └── mysql/
│       └── init.sql         # Init base de données
├── docker-compose.yml       # Orchestration des services
├── Dockerfile               # Image PHP/Symfony
├── .env.docker              # Template variables (à copier en .env)
└── Makefile                 # Raccourcis commandes
```

## 🔒 Sécurité

- Ne jamais committer le fichier `.env` (il est dans `.gitignore`)
- Le fichier `.env.docker` est un template sans vraies valeurs
- La clé Sodium doit être générée uniquement sur le serveur cible

---

*SecurBox — Coffre-fort numérique sécurisé | Diva Easy Informatique, Marrakech*
