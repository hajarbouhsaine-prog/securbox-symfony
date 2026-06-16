<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\User;
use App\Entity\WebAuthnCredential;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<WebAuthnCredential>
 */
class WebAuthnCredentialRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, WebAuthnCredential::class);
    }

    /**
     * Retourne toutes les clés actives d'un utilisateur, les plus récentes en premier.
     *
     * @return WebAuthnCredential[]
     */
    public function findByUser(User $user): array
    {
        return $this->createQueryBuilder('c')
            ->where('c.user = :user')
            ->setParameter('user', $user)
            ->orderBy('c.createdAt', 'DESC')
            ->getQuery()
            ->getResult();
    }
}
