<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\User;
use App\Entity\UserNotificationDismissal;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<UserNotificationDismissal>
 */
class UserNotificationDismissalRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, UserNotificationDismissal::class);
    }

    public function isDismissed(User $user, string $key): bool
    {
        return null !== $this->findOneBy(['user' => $user, 'notificationKey' => $key]);
    }

    public function dismiss(User $user, string $key): void
    {
        if (! $this->isDismissed($user, $key)) {
            $dismissal = new UserNotificationDismissal();
            $dismissal->setUser($user);
            $dismissal->setNotificationKey($key);
            $dismissal->setDismissedAt(new \DateTimeImmutable());
            $this->getEntityManager()->persist($dismissal);
            $this->getEntityManager()->flush();
        }
    }

    public function undismissAll(User $user): void
    {
        $this->createQueryBuilder('d')
            ->delete()
            ->where('d.user = :user')
            ->setParameter('user', $user)
            ->getQuery()
            ->execute();
    }
}
