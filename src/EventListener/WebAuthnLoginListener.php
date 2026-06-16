<?php

declare(strict_types=1);

namespace App\EventListener;

use App\Entity\WebAuthnCredential;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;

/**
 * Après un login réussi, si l'utilisateur a des clés FIDO2,
 * on le redirige vers la page de vérification WebAuthn.
 */
#[AsEventListener(event: LoginSuccessEvent::class)]
class WebAuthnLoginListener
{
    public function __construct(
        private EntityManagerInterface $em,
        private RouterInterface $router,
    ) {
    }

    public function __invoke(LoginSuccessEvent $event): void
    {
        $user = $event->getUser();

        // Vérifier si l'utilisateur a des clés FIDO2
        $credentials = $this->em->getRepository(WebAuthnCredential::class)
            ->findBy(['user' => $user]);

        if (empty($credentials)) {
            // Pas de clé FIDO2 → login normal, rien à faire
            return;
        }

        // Stocker l'état en session : 2FA requis
        $request = $event->getRequest();
        $session = $request->getSession();
        $session->set('2fa_webauthn_required', true);
        $session->set('2fa_webauthn_user_id', method_exists($user, 'getId') ? $user->getId() : null);
        $session->remove('2fa_webauthn_verified');

        // Rediriger vers la page 2FA WebAuthn
        $event->setResponse(
            new RedirectResponse($this->router->generate('app_2fa_webauthn'))
        );
    }
}
