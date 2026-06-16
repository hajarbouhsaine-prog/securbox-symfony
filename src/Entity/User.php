<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\UserRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;
use Scheb\TwoFactorBundle\Model\Totp\TotpConfiguration;
use Scheb\TwoFactorBundle\Model\Totp\TotpConfigurationInterface;
use Scheb\TwoFactorBundle\Model\Totp\TwoFactorInterface;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\UniqueConstraint(name: 'UNIQ_IDENTIFIER_EMAIL', fields: ['email'])]
#[UniqueEntity(fields: ['email'], message: 'There is already an account with this email')]
class User implements UserInterface, PasswordAuthenticatedUserInterface, TwoFactorInterface
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 180)]
    private ?string $email = null;

    #[ORM\Column]
    private array $roles = [];

    #[ORM\Column]
    private ?string $password = null;

    #[ORM\Column(length: 255)]
    private ?string $encryption_key_salt = null;

    #[ORM\Column]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\Column(nullable: true)]
    private ?\DateTimeImmutable $lastLoginAt = null;

    #[ORM\Column]
    private ?bool $isActive = null;

    #[ORM\Column]
    private bool $isVerified = false;

    #[ORM\Column(length: 100, nullable: true)]
    private ?string $verificationToken = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $securityQuestion = null;

    #[ORM\Column(length: 500, nullable: true)]
    private ?string $securityAnswerEncrypted = null;

    #[ORM\Column(length: 100, nullable: true)]
    private ?string $securityAnswerIv = null;

    #[ORM\Column(length: 255, nullable: true)]
    private ?string $totpSecret = null;

    #[ORM\Column]
    private bool $isTotpEnabled = false;

    #[ORM\OneToMany(targetEntity: Secret::class, mappedBy: 'user', orphanRemoval: true)]
    private Collection $secrets;

    #[ORM\OneToMany(targetEntity: AccessLog::class, mappedBy: 'user', cascade: ['remove'], orphanRemoval: true)]
    private Collection $accessLogs;

    #[ORM\OneToMany(targetEntity: \App\Entity\Collection::class, mappedBy: 'user', orphanRemoval: true)]
    private Collection $collections;

    #[ORM\OneToMany(targetEntity: UserNotificationDismissal::class, mappedBy: 'user', cascade: ['remove'])]
    private Collection $notificationDismissals;

    #[ORM\Column(length: 100, nullable: true)]
    private ?string $name = null;

    public function getName(): ?string
    {
        return $this->name;
    }

    public function setName(?string $name): self
    {
        $this->name = $name;

        return $this;
    }

    public function __construct()
    {
        $this->secrets = new ArrayCollection();
        $this->accessLogs = new ArrayCollection();
        $this->collections = new ArrayCollection();
        $this->notificationDismissals = new ArrayCollection();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): static
    {
        $this->email = $email;

        return $this;
    }

    public function getUserIdentifier(): string
    {
        return (string) $this->email;
    }

    public function getRoles(): array
    {
        $roles = $this->roles;
        $roles[] = 'ROLE_USER';

        return array_unique($roles);
    }

    public function setRoles(array $roles): static
    {
        $this->roles = $roles;

        return $this;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function setPassword(string $password): static
    {
        $this->password = $password;

        return $this;
    }

    #[\Deprecated]
    public function eraseCredentials(): void
    {
    }

    public function getEncryptionKeySalt(): ?string
    {
        return $this->encryption_key_salt;
    }

    public function setEncryptionKeySalt(string $encryption_key_salt): static
    {
        $this->encryption_key_salt = $encryption_key_salt;

        return $this;
    }

    public function getCreatedAt(): ?\DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function setCreatedAt(\DateTimeImmutable $createdAt): static
    {
        $this->createdAt = $createdAt;

        return $this;
    }

    public function getLastLoginAt(): ?\DateTimeImmutable
    {
        return $this->lastLoginAt;
    }

    public function setLastLoginAt(?\DateTimeImmutable $lastLoginAt): static
    {
        $this->lastLoginAt = $lastLoginAt;

        return $this;
    }

    public function isActive(): ?bool
    {
        return $this->isActive;
    }

    public function getIsActive(): bool
    {
        return $this->isActive;
    }

    public function setIsActive(bool $isActive): static
    {
        $this->isActive = $isActive;

        return $this;
    }

    public function isVerified(): bool
    {
        return $this->isVerified;
    }

    public function setIsVerified(bool $isVerified): self
    {
        $this->isVerified = $isVerified;

        return $this;
    }

    public function getVerificationToken(): ?string
    {
        return $this->verificationToken;
    }

    public function setVerificationToken(?string $verificationToken): self
    {
        $this->verificationToken = $verificationToken;

        return $this;
    }

    public function getSecurityQuestion(): ?string
    {
        return $this->securityQuestion;
    }

    public function setSecurityQuestion(?string $securityQuestion): self
    {
        $this->securityQuestion = $securityQuestion;

        return $this;
    }

    public function getSecurityAnswerEncrypted(): ?string
    {
        return $this->securityAnswerEncrypted;
    }

    public function setSecurityAnswerEncrypted(?string $securityAnswerEncrypted): self
    {
        $this->securityAnswerEncrypted = $securityAnswerEncrypted;

        return $this;
    }

    public function getSecurityAnswerIv(): ?string
    {
        return $this->securityAnswerIv;
    }

    public function setSecurityAnswerIv(?string $securityAnswerIv): self
    {
        $this->securityAnswerIv = $securityAnswerIv;

        return $this;
    }

    public function getSecrets(): Collection
    {
        return $this->secrets;
    }

    public function addSecret(Secret $secret): static
    {
        if (! $this->secrets->contains($secret)) {
            $this->secrets->add($secret);
            $secret->setUser($this);
        }

        return $this;
    }

    public function removeSecret(Secret $secret): static
    {
        if ($this->secrets->removeElement($secret)) {
            if ($secret->getUser() === $this) {
                $secret->setUser(null);
            }
        }

        return $this;
    }

    public function getAccessLogs(): Collection
    {
        return $this->accessLogs;
    }

    public function addAccessLog(AccessLog $accessLog): static
    {
        if (! $this->accessLogs->contains($accessLog)) {
            $this->accessLogs->add($accessLog);
            $accessLog->setUser($this);
        }

        return $this;
    }

    public function removeAccessLog(AccessLog $accessLog): static
    {
        if ($this->accessLogs->removeElement($accessLog)) {
            if ($accessLog->getUser() === $this) {
                $accessLog->setUser(null);
            }
        }

        return $this;
    }

    public function getCollections(): Collection
    {
        return $this->collections;
    }

    public function addCollection(\App\Entity\Collection $collection): static
    {
        if (! $this->collections->contains($collection)) {
            $this->collections->add($collection);
            $collection->setUser($this);
        }

        return $this;
    }

    public function removeCollection(\App\Entity\Collection $collection): static
    {
        if ($this->collections->removeElement($collection)) {
            if ($collection->getUser() === $this) {
                $collection->setUser(null);
            }
        }

        return $this;
    }

    public function getNotificationDismissals(): Collection
    {
        return $this->notificationDismissals;
    }

    public function addNotificationDismissal(UserNotificationDismissal $dismissal): static
    {
        if (! $this->notificationDismissals->contains($dismissal)) {
            $this->notificationDismissals->add($dismissal);
            $dismissal->setUser($this);
        }

        return $this;
    }

    public function removeNotificationDismissal(UserNotificationDismissal $dismissal): static
    {
        if ($this->notificationDismissals->removeElement($dismissal)) {
            if ($dismissal->getUser() === $this) {
                $dismissal->setUser(null);
            }
        }

        return $this;

    }

    public function getTotpSecret(): ?string
    {
        return $this->totpSecret;
    }

    public function setTotpSecret(?string $totpSecret): self
    {
        $this->totpSecret = $totpSecret;

        return $this;
    }

    public function isTotpEnabled(): bool
    {
        return $this->isTotpEnabled;
    }

    public function setIsTotpEnabled(bool $enabled): self
    {
        $this->isTotpEnabled = $enabled;

        return $this;
    }

    // Interface TwoFactorInterface
    public function isTotpAuthenticationEnabled(): bool
    {
        return $this->isTotpEnabled && null !== $this->totpSecret;
    }

    public function getTotpAuthenticationUsername(): string
    {
        return $this->email;
    }

    public function getTotpAuthenticationConfiguration(): ?TotpConfigurationInterface
    {
        return $this->totpSecret ? new TotpConfiguration($this->totpSecret, TotpConfiguration::ALGORITHM_SHA1, 30, 6) : null;
    }
}
