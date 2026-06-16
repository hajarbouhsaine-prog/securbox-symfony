<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class WebAuthn2faController extends AbstractController
{
    /**
     * Page de vérification FIDO2 post-login.
     * Accessible seulement si 2fa_webauthn_required est en session.
     */
    #[Route('/2fa/webauthn', name: 'app_2fa_webauthn', methods: ['GET'])]
    public function index(Request $request): Response
    {
        $session = $request->getSession();

        // Si déjà vérifié → vault
        if ($session->get('2fa_webauthn_verified')) {
            return $this->redirectToRoute('app_vault_index');
        }

        // Si pas de 2FA requis → login
        if (! $session->get('2fa_webauthn_required')) {
            return $this->redirectToRoute('app_login');
        }

        return $this->render('security/2fa_webauthn.html.twig');
    }

    /**
     * Appelé par le JS après vérification réussie de la signature.
     * Le WebAuthnController::authVerify() pose 2fa_webauthn_verified = true en session.
     * Cette route redirige ensuite vers le vault.
     */
    #[Route('/2fa/webauthn/success', name: 'app_2fa_webauthn_success', methods: ['GET'])]
    public function success(Request $request): Response
    {
        $session = $request->getSession();

        if (! $session->get('2fa_webauthn_verified')) {
            return $this->redirectToRoute('app_2fa_webauthn');
        }

        // Nettoyer les flags de session 2FA
        $session->remove('2fa_webauthn_required');

        return $this->redirectToRoute('app_vault_index');
    }
}
