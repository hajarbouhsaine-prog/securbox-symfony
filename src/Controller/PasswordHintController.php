<?php

declare(strict_types=1);

namespace App\Controller;

use App\Repository\UserRepository;
use App\Service\EncryptionService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;

class PasswordHintController extends AbstractController
{
    public function __construct(
        private EncryptionService $encryptionService,
        private RateLimiterFactory $passwordHintLimiter  // injecté automatiquement par Symfony
    ) {
    }

    #[Route('/password-hint', name: 'app_password_hint')]
    public function index(
        Request $request,
        UserRepository $userRepository,
        MailerInterface $mailer
    ): Response {
        $error   = null;
        $success = false;

        if ($request->isMethod('POST')) {

            // / Rate limiting — seulement sur POST
            $limiter = $this->passwordHintLimiter->create($request->getClientIp());
            if (! $limiter->consume(1)->isAccepted()) {
                $error = 'Trop de tentatives. Veuillez réessayer dans 10 minutes.';

                return $this->render('security/password_hint.html.twig', [
                    'error'   => $error,
                    'success' => false,
                ]);
            }

            $email = trim((string) $request->request->get('email', ''));
            $user  = $userRepository->findOneBy(['email' => $email]);

            // ── Toujours le même message (anti-énumération) ───────────────
            // On vérifie TOUT avant d'agir, mais on retourne toujours "success"
            // pour ne pas révéler si l'email existe ou non.
            if (
                $user
                && $user->getSecurityQuestion()
                && $user->getSecurityAnswerEncrypted()
            ) {
                $plainAnswer = $this->encryptionService->decryptWithAppSecret(
                    $user->getSecurityAnswerEncrypted(),
                    $user->getSecurityAnswerIv(),
                    $this->getParameter('kernel.secret')
                );

                $emailMessage = (new Email())
                    ->from('no-reply@securbox.local')
                    ->to($user->getEmail())
                    ->subject('🔐 Indice de mot de passe — SecurBox')
                    ->html($this->buildHintEmailHtml($user, $plainAnswer));

                $mailer->send($emailMessage);
            }
            // Qu'il existe ou non → on affiche toujours le même succès
            $success = true;
        }

        return $this->render('security/password_hint.html.twig', [
            'error'   => $error,
            'success' => $success,
        ]);
    }

    private function buildHintEmailHtml($user, string $plainAnswer): string
    {
        $question = htmlspecialchars($user->getSecurityQuestion());
        // On envoie l'indice (réponse), pas le mot de passe — c'est l'intention de l'app
        $hint = htmlspecialchars($plainAnswer);

        return <<<HTML
        <!DOCTYPE html>
        <html>
        <body style="font-family: Arial, sans-serif; background: #f4f4f4; padding: 40px; margin: 0;">
            <div style="max-width: 520px; margin: auto; background: white; border-radius: 12px; padding: 40px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #3b5bdb; font-size: 24px; margin: 0;">🔐 SecurBox</h1>
                    <p style="color: #868e96; font-size: 13px;">Coffre-fort numérique</p>
                </div>
                <h2 style="color: #212529;">Indice de mot de passe maître</h2>
                <p style="color: #495057; line-height: 1.6;">Bonjour,</p>
                <p style="color: #495057; line-height: 1.6;">
                    Voici votre question de sécurité et l'indice que vous avez enregistré :
                </p>
                <div style="background:#f8f9fa; border-left:4px solid #3b5bdb; padding:20px; border-radius:8px; margin:25px 0;">
                    <p style="margin:0 0 10px; font-weight:bold; color:#495057;">❓ Question :</p>
                    <p style="margin:0 0 20px; color:#212529;">{$question}</p>
                    <p style="margin:0 0 10px; font-weight:bold; color:#495057;">💡 Votre indice :</p>
                    <p style="margin:0; color:#212529; font-size:18px; font-weight:bold;">{$hint}</p>
                </div>
                <div style="background:#fff3cd; border-left:4px solid #dc3545; padding:15px; border-radius:8px;">
                    <p style="margin:0; color:#856404; font-size:12px; line-height:1.6;">
                        ⚠️ <strong>Supprimez cet email immédiatement</strong> après avoir retrouvé votre mot de passe.
                        Toute personne ayant accès à votre boîte mail pourrait lire cet indice.
                    </p>
                </div>
                <p style="color:#868e96; font-size:12px; margin-top:20px;">
                    Si vous n'avez pas demandé cet indice, ignorez cet email — votre compte reste sécurisé.
                </p>
                <hr style="border:none; border-top:1px solid #e9ecef; margin:25px 0;">
                <p style="color:#adb5bd; font-size:11px; text-align:center;">© SecurBox — Coffre-fort numérique sécurisé</p>
            </div>
        </body>
        </html>
        HTML;
    }
}
