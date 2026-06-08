<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\UserRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\UniqueConstraint(name: 'UNIQ_IDENTIFIER_EMAIL', fields: ['email'])]
#[UniqueEntity(fields: ['email'], message: 'There is already an account with this email')]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 180)]
    private ?string $email = null;

    /**
     * @var list<string> The user roles
     */
    #[ORM\Column]
    private array $roles = [];

    /**
     * @var string The hashed password
     */
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

    /**
     * @var Collection<int, Secret>
     */
    #[ORM\OneToMany(targetEntity: Secret::class, mappedBy: 'user', orphanRemoval: true)]
    private Collection $secrets;

    /**
     * @var Collection<int, AccessLog>
     */
    #[ORM\OneToMany(targetEntity: AccessLog::class, mappedBy: 'user')]
    private Collection $accessLogs;

    /**
     * @var Collection<int, \App\Entity\Collection>
     */
    #[ORM\OneToMany(targetEntity: \App\Entity\Collection::class, mappedBy: 'user', orphanRemoval: true)]
    private Collection $collections;

    public function __construct()
    {
        $this->secrets = new ArrayCollection();
        $this->accessLogs = new ArrayCollection();
        $this->collections = new ArrayCollection();
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

    /**
     * @return Collection<int, Secret>
     */
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

    /**
     * @return Collection<int, AccessLog>
     */
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

    /**
     * @return Collection<int, \App\Entity\Collection>
     */
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

    public function isVerified(): bool
    {
        return $this->isVerified;
    }

    public function setIsVerified(bool $isVerified): self
    {
        $this->isVerified = $isVerified;

        return $this;
    }
}
