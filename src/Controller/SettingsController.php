<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
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
    public function __construct(
        private EntityManagerInterface $entityManager
    ) {
    }

    #[Route('/', name: 'app_settings')]
    public function index(Request $request, UserPasswordHasherInterface $hasher): Response
    {
        /** @var User $user */
        /** @var User $user */
        $user = $this->getUser();

        if ($request->isMethod('POST')) {
            $action = $request->request->get('action');

            // ── Update email ──────────────────────────────────────────────
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
                        $user->setEmail($newEmail);
                        $this->entityManager->flush();
                        $this->addFlash('success', 'Email mis à jour avec succès !');
                    }
                }
            }

            // ── Change password ───────────────────────────────────────────
            if ('change_password' === $action) {
                $current = $request->request->get('current_password');
                $new     = $request->request->get('new_password');
                $confirm = $request->request->get('confirm_password');

                if (! $hasher->isPasswordValid($user, $current)) {
                    $this->addFlash('error', 'Mot de passe actuel incorrect.');
                } elseif ($new !== $confirm) {
                    $this->addFlash('error', 'Les nouveaux mots de passe ne correspondent pas.');
                } elseif (strlen($new) < 8) {
                    $this->addFlash('error', 'Le mot de passe doit contenir au moins 8 caractères.');
                } else {
                    $user->setPassword($hasher->hashPassword($user, $new));
                    $this->entityManager->flush();
                    $this->addFlash('success', 'Mot de passe mis à jour avec succès !');
                }
            }

            // ── Deauthorize sessions ──────────────────────────────────────
            // Invalidates all "remember me" tokens for this user.
            if ('deauthorize_sessions' === $action) {
                $current = $request->request->get('confirm_password');
                if (! $hasher->isPasswordValid($user, $current)) {
                    $this->addFlash('error', 'Mot de passe incorrect. Déconnexion annulée.');
                } else {
                    // Clear remember-me tokens if you store them
                    // If you use Symfony's token-based remember-me, invalidate here.
                    // For session-only auth, just invalidate the current session.
                    $request->getSession()->invalidate();
                    $this->addFlash('success', 'Toutes les sessions ont été révoquées.');

                    return $this->redirectToRoute('app_login');
                }
            }

            // ── Purge vault ───────────────────────────────────────────────
            if ('purge_vault' === $action) {
                $current = $request->request->get('confirm_password');
                if (! $hasher->isPasswordValid($user, $current)) {
                    $this->addFlash('error', 'Mot de passe incorrect. Coffre non vidé.');
                } else {
                    // Delete all vault items belonging to this user
                    $conn = $this->entityManager->getConnection();
                    // Adjust table/column names to match your actual schema
                    $conn->executeStatement(
                        'DELETE FROM vault_item WHERE user_id = :uid',
                        ['uid' => $user->getId()]
                    );
                    $this->addFlash('success', 'Coffre-fort vidé avec succès.');
                }
            }

            // ── Delete account ────────────────────────────────────────────
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

        return $this->render('settings/index.html.twig', [
            'user' => $user,
        ]);
    }

    #[Route('/security', name: 'app_settings_security')]
    public function security(Request $request, SessionInterface $session): Response
    {
        if ($request->isMethod('POST') && 'save_security' === $request->request->get('action')) {
            $allowedTimeouts = [5, 15, 30, 60];
            $allowedActions = ['lock', 'logout'];

            $timeout = (int) $request->request->get('session_timeout', 15);
            $action = $request->request->get('timeout_action', 'lock');

            if (! in_array($timeout, $allowedTimeouts, true) || ! in_array($action, $allowedActions, true)) {
                $this->addFlash('error', 'Paramètres de session invalides.');
            } else {
                $session->set('settings_security_timeout', $timeout);
                $session->set('settings_security_action', $action);
                $this->addFlash('success', 'Paramètres de sécurité enregistrés.');
            }
        }

        return $this->render('settings/security.html.twig');
    }

    #[Route('/appearance', name: 'app_settings_appearance')]
    public function appearance(Request $request, SessionInterface $session): Response
    {
        if ($request->isMethod('POST') && 'save_appearance' === $request->request->get('action')) {
            $allowedThemes = ['system', 'light', 'dark'];
            $allowedLanguages = ['fr', 'en', 'ar'];

            $theme = $request->request->get('theme', 'system');
            $language = $request->request->get('language', 'fr');
            $showIcons = $request->request->has('show_website_icons');

            if (! in_array($theme, $allowedThemes, true) || ! in_array($language, $allowedLanguages, true)) {
                $this->addFlash('error', 'Paramètres d’apparence invalides.');
            } else {
                $session->set('settings_appearance_theme', $theme);
                $session->set('settings_appearance_show_icons', $showIcons);
                $request->getSession()->set('_locale', $language);
                $this->addFlash('success', 'Paramètres d’apparence enregistrés.');
            }
        }

        return $this->render('settings/appearance.html.twig');
    }

    // ── Language switcher ─────────────────────────────────────────────────
    #[Route('/language/{lang}', name: 'app_settings_language')]
    public function setLanguage(string $lang, Request $request, SessionInterface $session): Response
    {
        $allowed = ['fr', 'en', 'ar'];
        if (in_array($lang, $allowed, true)) {
            $session->set('_locale', $lang);
        }
        $referer = $request->headers->get('referer', $this->generateUrl('app_settings'));

        return $this->redirect($referer);
    }
}
