-- Script d'initialisation SecurBox
-- Ce fichier est exécuté automatiquement au premier démarrage de MySQL

SET NAMES utf8mb4;
SET time_zone = '+00:00';

-- S'assurer que la BDD existe avec le bon charset
CREATE DATABASE IF NOT EXISTS `securbox`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE `securbox`;

-- Les tables seront créées par les migrations Doctrine
-- Ce script assure juste les bons paramètres de charset
