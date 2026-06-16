<?php

declare(strict_types=1);

namespace App\Service;

use App\Entity\AppSettings;
use App\Repository\AppSettingsRepository;
use Doctrine\ORM\EntityManagerInterface;

class AppSettingsService
{
    private ?AppSettings $settings = null;

    public function __construct(
        private AppSettingsRepository $repository,
        private EntityManagerInterface $em
    ) {
    }

    public function getSettings(): AppSettings
    {
        if (null === $this->settings) {
            $this->settings = $this->repository->getSettings();
        }

        return $this->settings;
    }

    public function getAppName(): string
    {
        return $this->getSettings()->getAppName();
    }

    public function getAppSlogan(): string
    {
        return $this->getSettings()->getAppSlogan();
    }

    public function getLogoUrl(): ?string
    {
        $filename = $this->getSettings()->getLogoFilename();

        return $filename ? '/uploads/app/' . $filename : null;
    }

    public function getPrimaryColor(): string
    {
        return $this->getSettings()->getPrimaryColor();
    }

    public function getAccentColor(): string
    {
        return $this->getSettings()->getAccentColor();
    }

    public function saveSettings(
        string $appName,
        string $appSlogan,
        string $primaryColor,
        string $accentColor,
        ?string $logoFilename = 'UNCHANGED'
    ): void {
        $settings = $this->getSettings();
        $settings->setAppName($appName);
        $settings->setAppSlogan($appSlogan);
        $settings->setPrimaryColor($primaryColor);
        $settings->setAccentColor($accentColor);

        if ('UNCHANGED' !== $logoFilename) {
            $settings->setLogoFilename($logoFilename);  // null = reset, string = nouveau logo
        }
        // Si 'UNCHANGED' → on ne touche pas au logo

        if (null === $settings->getId()) {
            $this->em->persist($settings);
        }
        $this->em->flush();
        $this->settings = $settings;
    }
}
