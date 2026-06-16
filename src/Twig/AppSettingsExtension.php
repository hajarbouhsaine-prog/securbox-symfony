<?php

declare(strict_types=1);

namespace App\Twig;

use App\Service\AppSettingsService;
use Twig\Extension\AbstractExtension;
use Twig\Extension\GlobalsInterface;

class AppSettingsExtension extends AbstractExtension implements GlobalsInterface
{
    public function __construct(private AppSettingsService $appSettingsService)
    {
    }

    public function getGlobals(): array
    {
        // On relit depuis le service à chaque requête HTTP
        // Le service lui-même met en cache dans $this->settings pour la durée d'une requête
        // → pas de valeurs stale entre requêtes
        $settings = $this->appSettingsService->getSettings();

        return [
            'app_name'     => $settings->getAppName(),
            'app_slogan'   => $settings->getAppSlogan(),
            'app_logo_url' => $settings->getLogoFilename()
                                ? '/uploads/app/' . $settings->getLogoFilename()
                                : null,
            'app_primary'  => $settings->getPrimaryColor(),
            'app_accent'   => $settings->getAccentColor(),
        ];
    }
}
