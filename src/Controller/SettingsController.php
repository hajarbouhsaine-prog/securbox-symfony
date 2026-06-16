<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Repository\WebAuthnCredentialRepository;  // ← AJOUTER
use App\Trait\LogsActionTrait;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[IsGranted('ROLE_USER')]
#[Route('/settings')]
class SettingsController extends AbstractController
{
    use LogsActionTrait;  // ← AJOUTER

    public function __construct(
        private EntityManagerInterface $entityManager,
        private WebAuthnCredentialRepository $webauthnRepo
    ) {
    }

    #[Route('/', name: 'app_settings')]
    public function index(Request $request, UserPasswordHasherInterface $hasher): Response
    {
        /** @var User $user */
        $user = $this->getUser();

        if ($request->isMethod('POST')) {
            $action = $request->request->get('action');
            if ('update_name' === $action) {

                $newName = trim($request->request->get('new_name', ''));

                if (empty($newName)) {

                    $this->addFlash('error', 'Le nom ne peut pas être vide.');

                } else {

                    $oldName = $user->getName();

                    $user->setName($newName);

                    $this->entityManager->flush();

                    $this->logAction(
                        $user,
                        'NAME_CHANGED',
                        $request,
                        'Nom modifié : ' . $oldName . ' → ' . $newName
                    );

                    $this->addFlash('success', 'Nom mis à jour avec succès !');
                }
            }

            if ('update_email' === $action) {
                $current  = $request->request->get('current_password');
                $newEmail = trim($request->request->get('new_email', ''));

                if (! $hasher->isPasswordValid($user, $current)) {
                    $this->addFlash('error', 'Mot de passe actuel incorrect.');
                } elseif (! filter_var($newEmail, FILTER_VALIDATE_EMAIL)) {
                    $this->addFlash('error', 'Veuillez renseigner une adresse email valide.');
                } else {
                    $existing = $this->entityManager->getRepository(User::class)
                        ->findOneBy(['email' => $newEmail]);
                    if ($existing && $existing !== $user) {
                        $this->addFlash('error', 'Cette adresse email est déjà utilisée.');
                    } else {
                        $oldEmail = $user->getEmail();
                        $user->setEmail($newEmail);
                        $this->entityManager->flush();
                        // ── LOG ──────────────────────────────────────────
                        $this->logAction(
                            $user,
                            'EMAIL_CHANGED',
                            $request,
                            'Email changé : ' . $oldEmail . ' → ' . $newEmail
                        );
                        $this->addFlash('success', 'Email mis à jour avec succès !');
                    }
                }
            }

            if ('deauthorize_sessions' === $action) {
                $current = $request->request->get('confirm_password');
                if (! $hasher->isPasswordValid($user, $current)) {
                    $this->addFlash('error', 'Mot de passe incorrect. Déconnexion annulée.');
                } else {
                    $request->getSession()->invalidate();
                    $this->addFlash('success', 'Toutes les sessions ont été révoquées.');

                    return $this->redirectToRoute('app_login');
                }
            }

            if ('purge_vault' === $action) {
                $current = $request->request->get('confirm_password');
                if (! $hasher->isPasswordValid($user, $current)) {
                    $this->addFlash('error', 'Mot de passe incorrect. Coffre non vidé.');
                } else {
                    $conn = $this->entityManager->getConnection();
                    $conn->executeStatement('DELETE FROM secret WHERE user_id = :uid', ['uid' => $user->getId()]);
                    $this->addFlash('success', 'Coffre-fort vidé avec succès.');
                }
            }

            if ('delete_account' === $action) {
                $current = $request->request->get('confirm_password');
                if (! $hasher->isPasswordValid($user, $current)) {
                    $this->addFlash('error', 'Mot de passe incorrect. Compte non supprimé.');
                } else {
                    $request->getSession()->invalidate();
                    $this->entityManager->remove($user);
                    $this->entityManager->flush();

                    return $this->redirectToRoute('app_register');
                }
            }
        }

        return $this->render('settings/index.html.twig', ['user' => $user]);
    }

    #[Route('/security', name: 'app_settings_security')]
    public function security(Request $request, SessionInterface $session, UserPasswordHasherInterface $hasher): Response
    {
        /** @var User $user */
        $user = $this->getUser();

        if ($request->isMethod('POST')) {
            $action = $request->request->get('action');

            if ('save_security' === $action) {
                $allowedTimeouts = [0, 1, 5, 15, 30, 60, 240];
                $allowedActions  = ['lock', 'logout'];
                $timeout         = (int) $request->request->get('session_timeout', 15);
                $timeoutAction   = $request->request->get('timeout_action', 'lock');

                if (! in_array($timeout, $allowedTimeouts, true) || ! in_array($timeoutAction, $allowedActions, true)) {
                    $this->addFlash('error', 'Paramètres invalides.');
                } else {
                    $session->set('settings_security_timeout', $timeout);
                    $session->set('settings_security_action', $timeoutAction);
                    $session->set('vault_last_activity', time());
                    $this->addFlash('success', 'Paramètres de session enregistrés.');
                }
            }

            if ('change_password' === $action) {
                $current = $request->request->get('current_password', '');
                $new     = $request->request->get('new_password', '');
                $confirm = $request->request->get('confirm_new_password', '');

                if (! $hasher->isPasswordValid($user, $current)) {
                    $this->addFlash('error', 'Mot de passe actuel incorrect.');
                } elseif (strlen($new) < 8) {
                    $this->addFlash('error', 'Le nouveau mot de passe doit contenir au moins 8 caractères.');
                } elseif ($new !== $confirm) {
                    $this->addFlash('error', 'Les nouveaux mots de passe ne correspondent pas.');
                } else {
                    $user->setPassword($hasher->hashPassword($user, $new));
                    $this->entityManager->flush();
                    // ── LOG ──────────────────────────────────────────
                    $this->logAction(
                        $user,
                        'PASSWORD_CHANGED',
                        $request,
                        'Mot de passe maître modifié'
                    );
                    $request->getSession()->invalidate();
                    $this->addFlash('success', 'Mot de passe maître mis à jour. Veuillez vous reconnecter.');

                    return $this->redirectToRoute('app_login');
                }
            }

            if ('revoke_session' === $action) {
                $sessionDbId = (int) $request->request->get('session_id');
                $userSession = $this->entityManager
                    ->getRepository(\App\Entity\UserSession::class)
                    ->find($sessionDbId);

                if ($userSession && $userSession->getUser() === $user) {
                    $userSession->revoke();
                    $this->entityManager->flush();
                    $this->addFlash('success', 'Session révoquée.');
                }

                return $this->redirectToRoute('app_settings_security');
            }
        }

        $currentSessionId = $request->getSession()->getId();
        $sessions = $this->entityManager
            ->getRepository(\App\Entity\UserSession::class)
            ->findActiveByUser($user->getId());

        return $this->render('settings/security.html.twig', [
            'sessions'         => $sessions,
            'currentSessionId' => $currentSessionId,
            'webauthnRepo'     => $this->webauthnRepo,
        ]);
    }

    #[Route('/appearance', name: 'app_settings_appearance')]
    public function appearance(Request $request, SessionInterface $session): Response
    {
        if ($request->isMethod('POST') && 'save_appearance' === $request->request->get('action')) {
            $allowedThemes    = ['system', 'light', 'dark'];
            $allowedLanguages = ['fr', 'en', 'ar'];
            $theme    = $request->request->get('theme', 'dark');
            $language = $request->request->get('language', 'fr');
            $showIcons = $request->request->has('show_website_icons');
            $maskPwd   = $request->request->has('mask_passwords');

            if (! in_array($theme, $allowedThemes, true) || ! in_array($language, $allowedLanguages, true)) {
                $this->addFlash('error', 'Paramètres invalides.');
            } else {
                $session->set('settings_appearance_theme', $theme);
                $session->set('settings_appearance_show_icons', $showIcons);
                $session->set('settings_appearance_mask_pwd', $maskPwd);
                $session->set('_locale', $language);
                $request->setLocale($language);
                $this->addFlash('success', 'Préférences d\'apparence enregistrées.');
            }
        }

        return $this->render('settings/appearance.html.twig');
    }

    #[Route('/language/{lang}', name: 'app_settings_language')]
    public function setLanguage(string $lang, Request $request, SessionInterface $session): Response
    {
        $allowed = ['fr', 'en', 'ar'];
        if (in_array($lang, $allowed, true)) {
            $session->set('_locale', $lang);
            $request->setLocale($lang);
        }
        $referer = $request->headers->get('referer', $this->generateUrl('app_settings'));

        return $this->redirect($referer);
    }
}
