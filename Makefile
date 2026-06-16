# ─────────────────────────────────────────────────────────────
#  SecurBox — Makefile Docker
#  Usage : make <commande>
# ─────────────────────────────────────────────────────────────

.PHONY: help build up down restart logs shell migrate fixtures clean

help: ## Afficher l'aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Construire les images Docker
	docker compose build --no-cache

up: ## Démarrer SecurBox
	docker compose up -d
	@echo "✅ SecurBox lancé !"
	@echo "   🌐 App      → http://localhost:8080"
	@echo "   🗃️  phpMyAdmin → http://localhost:8081"

down: ## Arrêter SecurBox
	docker compose down

restart: ## Redémarrer les conteneurs
	docker compose restart

logs: ## Voir les logs en temps réel
	docker compose logs -f

logs-app: ## Logs de l'app PHP uniquement
	docker compose logs -f app

shell: ## Ouvrir un terminal dans le conteneur PHP
	docker compose exec app bash

migrate: ## Exécuter les migrations Doctrine
	docker compose exec app php bin/console doctrine:migrations:migrate --no-interaction

fixtures: ## Charger les fixtures (données de test)
	docker compose exec app php bin/console doctrine:fixtures:load --no-interaction

cache-clear: ## Vider le cache Symfony
	docker compose exec app php bin/console cache:clear

clean: ## Supprimer les conteneurs ET les volumes (⚠️ supprime la BDD !)
	docker compose down -v
	@echo "⚠️  Volumes supprimés — la base de données est vide."

status: ## Voir l'état des conteneurs
	docker compose ps
