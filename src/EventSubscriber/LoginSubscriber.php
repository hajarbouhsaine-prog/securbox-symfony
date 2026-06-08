<?php

declare(strict_types=1);

namespace App\EventSubscriber;

use App\Service\AuditService;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

class LoginSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private AuditService $auditService
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            LoginSuccessEvent::class => 'onLoginSuccess',
        ];
    }

    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getAuthenticatedToken()->getUser();
        if (! $user instanceof \App\Entity\User) {
            return;
        }
        $this->auditService->log('LOGIN', $user);
    }
}
