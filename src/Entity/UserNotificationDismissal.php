<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\UserNotificationDismissalRepository;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: UserNotificationDismissalRepository::class)]
class UserNotificationDismissal
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\ManyToOne(inversedBy: 'notificationDismissals')]
    #[ORM\JoinColumn(nullable: false)]
    private ?User $user = null;

    #[ORM\Column(length: 100)]
    private ?string $notificationKey = null;

    #[ORM\Column]
    private ?\DateTimeImmutable $dismissedAt = null;

    // Getters / setters
    public function getId(): ?int
    {
        return $this->id;
    }

    public function getUser(): ?User
    {
        return $this->user;
    }

    public function setUser(?User $user): static
    {
        $this->user = $user;

        return $this;
    }

    public function getNotificationKey(): ?string
    {
        return $this->notificationKey;
    }

    public function setNotificationKey(string $key): static
    {
        $this->notificationKey = $key;

        return $this;
    }

    public function getDismissedAt(): ?\DateTimeImmutable
    {
        return $this->dismissedAt;
    }

    public function setDismissedAt(\DateTimeImmutable $at): static
    {
        $this->dismissedAt = $at;

        return $this;
    }
}
