<?php

declare(strict_types=1);

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: \App\Repository\WebAuthnCredentialRepository::class)]
#[ORM\Table(name: 'webauthn_credential')]
class WebAuthnCredential
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private ?int $id = null;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    private User $user;

    /** Identifiant binaire retourné par l'authenticator (base64url encodé) */
    #[ORM\Column(type: 'text', unique: true)]
    private string $credentialId;

    /** Clé publique COSE encodée en base64 */
    #[ORM\Column(type: 'text')]
    private string $publicKey;

    /** Compteur de signatures — détecte les clones de clé */
    #[ORM\Column(type: 'integer')]
    private int $signCount = 0;

    /** Nom donné par l'utilisateur (ex: "Ma YubiKey", "MacBook TouchID") */
    #[ORM\Column(type: 'string', length: 100)]
    private string $name;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    #[ORM\Column(type: 'datetime_immutable', nullable: true)]
    private ?\DateTimeImmutable $lastUsedAt = null;

    public function __construct(User $user, string $credentialId, string $publicKey, string $name)
    {
        $this->user         = $user;
        $this->credentialId = $credentialId;
        $this->publicKey    = $publicKey;
        $this->name         = $name;
        $this->createdAt    = new \DateTimeImmutable();
    }

    // ── Getters & Setters ──────────────────────────────────────────

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getUser(): User
    {
        return $this->user;
    }

    public function getCredentialId(): string
    {
        return $this->credentialId;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function getSignCount(): int
    {
        return $this->signCount;
    }

    public function setSignCount(int $count): void
    {
        $this->signCount = $count;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function getLastUsedAt(): ?\DateTimeImmutable
    {
        return $this->lastUsedAt;
    }

    public function markUsed(): void
    {
        $this->lastUsedAt = new \DateTimeImmutable();
    }
}
