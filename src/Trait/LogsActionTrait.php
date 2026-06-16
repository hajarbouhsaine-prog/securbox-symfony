<?php

declare(strict_types=1);

namespace App\Trait;

use App\Entity\AccessLog;
use App\Entity\User;
use Symfony\Component\HttpFoundation\Request;

trait LogsActionTrait
{
    private function logAction(
        User $user,
        string $action,
        Request $request,
        ?string $details = null
    ): void {
        $log = new AccessLog();
        $log->setUser($user);
        $log->setAction($action);
        $log->setIpAddress($request->getClientIp() ?? '0.0.0.0');
        $log->setUserAgent($request->headers->get('User-Agent', ''));
        $log->setDetails($details);
        $log->setCreatedAt(new \DateTimeImmutable());
        $this->entityManager->persist($log);
        $this->entityManager->flush();
    }
}
