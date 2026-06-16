<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Trait\LogsActionTrait;          // ← AJOUTER
use Doctrine\ORM\EntityManagerInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\Totp\TotpAuthenticatorInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[IsGranted('ROLE_USER')]
#[Route('/settings/security/2fa')]
class TotpController extends AbstractController
{
    use LogsActionTrait;                 // ← AJOUTER

    public function __construct(
        private TotpAuthenticatorInterface $totpAuthenticator,
        private EntityManagerInterface $entityManager
    ) {
    }

    #[Route('/enable', name: 'app_2fa_enable', methods: ['GET'])]
    public function enable(): Response
    {
        /** @var User $user */
        $user = $this->getUser();
        if (! $user->getTotpSecret()) {
            $secret = $this->totpAuthenticator->generateSecret();
            $user->setTotpSecret($secret);
            $this->entityManager->flush();
        }
        $qrCodeUrl = $this->totpAuthenticator->getQRContent($user);

        return $this->render('security/2fa_enable.html.twig', [
            'qrCodeUrl' => $qrCodeUrl,
            'secret'    => $user->getTotpSecret(),
        ]);
    }

    #[Route('/confirm', name: 'app_2fa_confirm', methods: ['POST'])]
    public function confirm(Request $request): Response
    {
        /** @var User $user */
        $user = $this->getUser();
        $code = $request->request->get('code', '');

        if ($this->totpAuthenticator->checkCode($user, $code)) {
            $user->setIsTotpEnabled(true);
            $this->entityManager->flush();

            // ── LOG 2FA activé ──────────────────────────────────
            $this->logAction(
                $user,
                '2FA_ENABLED',
                $request,
                'Double authentification activée via TOTP'
            );

            $this->addFlash('success', '✅ Double authentification activée avec succès !');

            return $this->redirectToRoute('app_settings_security');
        }

        $this->addFlash('error', '❌ Code incorrect. Réessayez.');

        return $this->redirectToRoute('app_2fa_enable');
    }

    #[Route('/disable', name: 'app_2fa_disable', methods: ['POST'])]
    public function disable(Request $request): Response
    {
        /** @var User $user */
        $user = $this->getUser();

        if (! $this->isCsrfTokenValid('2fa_disable', $request->request->get('_token'))) {
            $this->addFlash('error', 'Token invalide.');

            return $this->redirectToRoute('app_settings_security');
        }

        $user->setIsTotpEnabled(false);
        $user->setTotpSecret(null);
        $this->entityManager->flush();

        // ── LOG 2FA désactivé ───────────────────────────────────
        $this->logAction(
            $user,
            '2FA_DISABLED',
            $request,
            'Double authentification désactivée'
        );

        $this->addFlash('success', '✅ Double authentification désactivée.');

        return $this->redirectToRoute('app_settings_security');
    }
}
