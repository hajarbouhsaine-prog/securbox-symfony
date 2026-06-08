<?php

declare(strict_types=1);

namespace App\Service;

use App\Entity\AccessLog;
use App\Entity\Secret;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

class AuditService
{
    public function __construct(
        private EntityManagerInterface $entityManager,
        private RequestStack $requestStack
    ) {
    }

    public function log(
        string $action,
        User $user,
        ?Secret $secret = null
    ): void {
        $request = $this->requestStack->getCurrentRequest();

        $log = new AccessLog();
        $log->setAction($action);
        $log->setUser($user);
        $log->setSecret($secret);
        $log->setIpAddress($request?->getClientIp() ?? '0.0.0.0');
        $log->setUserAgent($request?->headers->get('User-Agent') ?? '');
        $log->setCreatedAt(new \DateTimeImmutable());

        $this->entityManager->persist($log);
        $this->entityManager->flush();
    }
}
