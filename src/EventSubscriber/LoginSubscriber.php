<?php

declare(strict_types=1);

namespace App\EventSubscriber;

use App\Entity\User;
use App\Entity\UserSession;
use App\Service\AuditService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

class LoginSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private AuditService $auditService,
        private RequestStack $requestStack,
        private EntityManagerInterface $em,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [LoginSuccessEvent::class => 'onLoginSuccess'];
    }

    public function onLoginSuccess(LoginSuccessEvent $event): void
    {
        $user = $event->getAuthenticatedToken()->getUser();
        if (! $user instanceof User) {
            return;
        }

        $request = $this->requestStack->getCurrentRequest();
        if ($request) {
            // Stocke le mot de passe pour le chiffrement
            $plainPassword = $request->request->get('_password', '');
            if ('' !== $plainPassword) {
                $request->getSession()->set('vault_master_password', $plainPassword);
            }

            // Enregistre la session en DB
            $ip        = $request->getClientIp() ?? '0.0.0.0';
            $ua        = $request->headers->get('User-Agent', 'Unknown');
            $sessionId = $request->getSession()->getId();

            $userSession = new UserSession($user, $ip, $ua, $sessionId);
            $this->em->persist($userSession);
            $this->em->flush();
        }

        $this->auditService->log('LOGIN', $user);
    }
}
