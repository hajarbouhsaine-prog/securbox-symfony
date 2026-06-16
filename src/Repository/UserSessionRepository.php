<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\UserSession;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

class UserSessionRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, UserSession::class);
    }

    public function findActiveByUser(int $userId): array
    {
        return $this->createQueryBuilder('s')
            ->where('s.user = :uid')
            ->andWhere('s.isActive = true')
            ->setParameter('uid', $userId)
            ->orderBy('s.lastActivityAt', 'DESC')
            ->getQuery()
            ->getResult();
    }

    public function revokeAllByUser(int $userId): void
    {
        $this->createQueryBuilder('s')
            ->update()
            ->set('s.isActive', 'false')
            ->where('s.user = :uid')
            ->setParameter('uid', $userId)
            ->getQuery()
            ->execute();
    }
}
