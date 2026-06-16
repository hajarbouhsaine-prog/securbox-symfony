<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\UserSessionRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: UserSessionRepository::class)]
#[ORM\Table(name: 'user_session')]
class UserSession
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    private User $user;

    #[ORM\Column(length: 45)]
    private string $ipAddress;

    #[ORM\Column(length: 500)]
    private string $userAgent;

    #[ORM\Column]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column]
    private \DateTimeImmutable $lastActivityAt;

    #[ORM\Column(length: 100, nullable: true)]
    private ?string $sessionId = null;

    #[ORM\Column]
    private bool $isActive = true;

    public function __construct(User $user, string $ip, string $ua, string $sessionId)
    {
        $this->user           = $user;
        $this->ipAddress      = $ip;
        $this->userAgent      = substr($ua, 0, 500);
        $this->sessionId      = $sessionId;
        $this->createdAt      = new \DateTimeImmutable();
        $this->lastActivityAt = new \DateTimeImmutable();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getUser(): User
    {
        return $this->user;
    }

    public function getIpAddress(): string
    {
        return $this->ipAddress;
    }

    public function getUserAgent(): string
    {
        return $this->userAgent;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function getLastActivityAt(): \DateTimeImmutable
    {
        return $this->lastActivityAt;
    }

    public function getSessionId(): ?string
    {
        return $this->sessionId;
    }

    public function isActive(): bool
    {
        return $this->isActive;
    }

    public function revoke(): self
    {
        $this->isActive = false;

        return $this;
    }

    public function touch(): self
    {
        $this->lastActivityAt = new \DateTimeImmutable();

        return $this;
    }

    public function getDeviceName(): string
    {
        $ua = $this->userAgent;
        if (str_contains($ua, 'iPhone') || str_contains($ua, 'iPad')) {
            return 'iOS';
        }
        if (str_contains($ua, 'Android')) {
            return 'Android';
        }
        if (str_contains($ua, 'Edg/')) {
            return 'Microsoft Edge';
        }
        if (str_contains($ua, 'Chrome')) {
            return 'Google Chrome';
        }
        if (str_contains($ua, 'Safari')) {
            return 'Safari';
        }
        if (str_contains($ua, 'Firefox')) {
            return 'Firefox';
        }

        return 'Navigateur Web';
    }

    public function getDeviceIcon(): string
    {
        $ua = $this->userAgent;
        if (str_contains($ua, 'iPhone') || str_contains($ua, 'iPad') || str_contains($ua, 'Android')) {
            return 'fas fa-mobile-alt';
        }

        return 'fas fa-desktop';
    }
}
