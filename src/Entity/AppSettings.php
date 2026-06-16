<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\AppSettingsRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: AppSettingsRepository::class)]
class AppSettings
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 100)]
    private string $appName = 'SecurBox';

    #[ORM\Column(length: 255)]
    private string $appSlogan = 'Coffre-fort numérique';

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $logoFilename = null;

    #[ORM\Column(length: 7)]
    private string $primaryColor = '#6fbfff';

    #[ORM\Column(length: 7)]
    private string $accentColor = '#4dd4ac';

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getAppName(): string
    {
        return $this->appName;
    }

    public function setAppName(string $appName): self
    {
        $this->appName = $appName;

        return $this;
    }

    public function getAppSlogan(): string
    {
        return $this->appSlogan;
    }

    public function setAppSlogan(string $appSlogan): self
    {
        $this->appSlogan = $appSlogan;

        return $this;
    }

    public function getLogoFilename(): ?string
    {
        return $this->logoFilename;
    }

    public function setLogoFilename(?string $logoFilename): self
    {
        $this->logoFilename = $logoFilename;

        return $this;
    }

    public function getPrimaryColor(): string
    {
        return $this->primaryColor;
    }

    public function setPrimaryColor(string $primaryColor): self
    {
        $this->primaryColor = $primaryColor;

        return $this;
    }

    public function getAccentColor(): string
    {
        return $this->accentColor;
    }

    public function setAccentColor(string $accentColor): self
    {
        $this->accentColor = $accentColor;

        return $this;
    }
}
