FROM php:8.4-fpm

# Arguments pour l'utilisateur
ARG user=symfony
ARG uid=1000

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    git \
    curl \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    libzip-dev \
    libsodium-dev \
    zip \
    unzip \
    nodejs \
    npm \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Installer les extensions PHP nécessaires pour SecurBox
RUN docker-php-ext-install \
    pdo \
    pdo_mysql \
    mbstring \
    exif \
    pcntl \
    bcmath \
    gd \
    zip \
    sodium

# Installer Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Créer un utilisateur système pour Symfony
RUN useradd -G www-data,root -u $uid -d /home/$user $user
RUN mkdir -p /home/$user/.composer && \
    chown -R $user:$user /home/$user

# Définir le dossier de travail
WORKDIR /var/www

# Copier d'abord les fichiers de dépendances
COPY composer.json composer.lock* ./

# Installer les dépendances PHP (sans les scripts pour l'instant)
RUN composer install --no-scripts --no-autoloader --prefer-dist --no-interaction

# Copier le reste du projet
COPY . .

# Générer l'autoloader optimisé
RUN composer dump-autoload --optimize

# Installer les dépendances JS si package.json existe
RUN if [ -f "package.json" ]; then npm install && npm run build; fi

# Permissions correctes pour Symfony
RUN mkdir -p /var/www/var && chown -R $user:www-data /var/www && \
    chmod -R 775 /var/www/var

USER $user

EXPOSE 9000
CMD ["php-fpm"]
