<?php

declare(strict_types=1);

namespace App\Service;

use App\Entity\User;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class EmailVerificationService
{
    public function __construct(
        private MailerInterface $mailer,
        private UrlGeneratorInterface $router
    ) {
    }

    public function setVerificationToken(User $user): void
    {
        $token = bin2hex(random_bytes(32));
        $user->setVerificationToken($token);
    }

    public function sendVerificationEmail(User $user): void
    {
        $verifyUrl = $this->router->generate(
            'app_verify_email',
            ['token' => $user->getVerificationToken()],
            UrlGeneratorInterface::ABSOLUTE_URL
        );

        $email = (new Email())
            ->from('no-reply@securbox.local')
            ->to($user->getEmail())
            ->subject('🔐 Vérifiez votre adresse email — SecurBox')
            ->html($this->buildEmailHtml($user, $verifyUrl));

        $this->mailer->send($email);
    }

    private function buildEmailHtml(User $user, string $verifyUrl): string
    {
        return <<<HTML
        <!DOCTYPE html>
        <html>
        <body style="font-family: Arial, sans-serif; background: #f4f4f4; padding: 40px; margin: 0;">
            <div style="max-width: 520px; margin: auto; background: white; border-radius: 12px; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.08);">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #3b5bdb; font-size: 24px; margin: 0;">🔐 SecurBox</h1>
                    <p style="color: #868e96; font-size: 13px; margin: 5px 0 0;">Coffre-fort numérique</p>
                </div>
                <h2 style="color: #212529; font-size: 20px;">Vérification de votre email</h2>
                <p style="color: #495057; line-height: 1.6;">Bonjour,</p>
                <p style="color: #495057; line-height: 1.6;">
                    Merci de vous être inscrit sur <strong>SecurBox</strong>.
                    Veuillez confirmer votre adresse email en cliquant sur le bouton ci-dessous :
                </p>
                <div style="text-align: center; margin: 35px 0;">
                    <a href="{$verifyUrl}"
                       style="background: #3b5bdb; color: white; padding: 14px 35px; border-radius: 8px;
                              text-decoration: none; font-weight: bold; font-size: 15px; display: inline-block;">
                        ✅ Vérifier mon email
                    </a>
                </div>
                <p style="color: #868e96; font-size: 12px; line-height: 1.6;">
                    Ce lien est valable <strong>24 heures</strong>.
                    Si vous n'avez pas créé de compte sur SecurBox, ignorez cet email.
                </p>
                <hr style="border: none; border-top: 1px solid #e9ecef; margin: 25px 0;">
                <p style="color: #adb5bd; font-size: 11px; text-align: center;">
                    © SecurBox — Coffre-fort numérique sécurisé
                </p>
            </div>
        </body>
        </html>
        HTML;
    }
}
