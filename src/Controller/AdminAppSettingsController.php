<?php

declare(strict_types=1);

namespace App\Controller;

use App\Service\AppSettingsService;
use App\Trait\LogsActionTrait;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
// AJOUTÉ : Importation requise pour typer l'EntityManager dans le constructeur
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[IsGranted('ROLE_ADMIN')]
#[Route('/admin/app-settings')]
class AdminAppSettingsController extends AbstractController
{
    use LogsActionTrait;

    // Constructeur modifié avec l'injection de l'EntityManagerInterface
    public function __construct(
        private AppSettingsService $appSettingsService,
        private EntityManagerInterface $entityManager
    ) {
    }

    #[Route('/', name: 'app_admin_app_settings')]
    public function index(Request $request): Response
    {
        if ($request->isMethod('POST')) {
            $appName   = trim($request->request->get('app_name', 'SecurBox'));
            $appSlogan = trim($request->request->get('app_slogan', 'Coffre-fort numérique'));
            $primary   = $request->request->get('primary_color', '#6fbfff');
            $accent    = $request->request->get('accent_color', '#4dd4ac');

            // 'UNCHANGED' = ne pas toucher au logo existant
            $logoFilename = 'UNCHANGED';
            $logoFile = $request->files->get('logo');

            if ($logoFile) {
                $allowed = ['image/jpeg', 'image/png', 'image/webp', 'image/svg+xml'];
                $maxSize = 2 * 1024 * 1024;

                if (! in_array($logoFile->getMimeType(), $allowed)) {
                    $this->addFlash('error', 'Format non supporté. JPG, PNG, WEBP ou SVG uniquement.');

                    return $this->redirectToRoute('app_admin_app_settings');
                }
                if ($logoFile->getSize() > $maxSize) {
                    $this->addFlash('error', 'Logo trop lourd. Maximum 2MB.');

                    return $this->redirectToRoute('app_admin_app_settings');
                }

                // Supprimer l'ancien logo
                $oldLogo = $this->appSettingsService->getSettings()->getLogoFilename();
                if ($oldLogo) {
                    $oldPath = $this->getParameter('kernel.project_dir') . '/public/uploads/app/' . $oldLogo;
                    if (file_exists($oldPath)) {
                        unlink($oldPath);
                    }
                }

                $logoFilename = 'logo_' . uniqid() . '.' . $logoFile->guessExtension();
                $logoFile->move(
                    $this->getParameter('kernel.project_dir') . '/public/uploads/app/',
                    $logoFilename
                );
            }

            // Validation couleurs hex
            if (! preg_match('/^#[0-9A-Fa-f]{6}$/', $primary)) {
                $primary = '#6fbfff';
            }
            if (! preg_match('/^#[0-9A-Fa-f]{6}$/', $accent)) {
                $accent  = '#4dd4ac';
            }
            if (empty($appName)) {
                $appName = 'SecurBox';
            }

            $this->appSettingsService->saveSettings($appName, $appSlogan, $primary, $accent, $logoFilename);
            $this->addFlash('success', 'Paramètres de l\'application mis à jour !');

            // AJOUTÉ : Construction du détail du log et exécution
            $changes = 'Nom: ' . $appName . ', Couleur: ' . $primary;
            if ($logoFile) {
                $changes .= ', Logo mis à jour';
            }
            /** @var \App\Entity\User $adminUser */
            $adminUser = $this->getUser();
            $this->logAction($adminUser, 'ADMIN_SETTINGS_CHANGED', $request, $changes);

            return $this->redirectToRoute('app_admin_app_settings');
        }

        return $this->render('admin/app_settings.html.twig', [
            'settings' => $this->appSettingsService->getSettings(),
        ]);
    }

    #[Route('/reset-logo', name: 'app_admin_reset_logo', methods: ['POST'])]
    // MODIFIÉ : Injection de Request pour permettre l'utilisation de $request dans le logAction
    public function resetLogo(Request $request): Response
    {
        $settings = $this->appSettingsService->getSettings();

        // Supprimer le fichier physique si existant
        if ($settings->getLogoFilename()) {
            $path = $this->getParameter('kernel.project_dir') . '/public/uploads/app/' . $settings->getLogoFilename();
            if (file_exists($path)) {
                unlink($path);
            }
        }

        // null EXPLICITE (pas 'UNCHANGED') pour vraiment effacer le logo en DB
        $this->appSettingsService->saveSettings(
            $settings->getAppName(),
            $settings->getAppSlogan(),
            $settings->getPrimaryColor(),
            $settings->getAccentColor(),
            null  // ← reset logo → retour au cadenas par défaut
        );

        $this->addFlash('success', 'Logo réinitialisé.');

        // AJOUTÉ : Log juste avant la redirection finale du reset logo
        /** @var \App\Entity\User $adminUser */
        $adminUser = $this->getUser();
        $this->logAction($adminUser, 'ADMIN_SETTINGS_CHANGED', $request, 'Logo réinitialisé');

        return $this->redirectToRoute('app_admin_app_settings');
    }
}
