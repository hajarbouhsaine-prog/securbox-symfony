<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\AccessLog;
use App\Entity\Secret;
use App\Entity\User;
use App\Repository\UserNotificationDismissalRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[IsGranted('ROLE_USER')]
class NotificationController extends AbstractController
{
    public function __construct(
        private EntityManagerInterface $entityManager,
        private UserNotificationDismissalRepository $dismissalRepo,
    ) {
    }

    #[Route('/notifications', name: 'app_notifications', methods: ['GET'])]
    public function index(): JsonResponse
    {
        try {
            /** @var User $user */
            $user = $this->getUser();
            $notifications = [];
            $now = new \DateTimeImmutable();

            // ── Helpers ──
            $isDismissed = fn (string $key): bool => $this->dismissalRepo->isDismissed($user, $key);

            // ════════════════════════════════════════════════════════
            // 1. CONNEXIONS — dernières 5 depuis AccessLog
            // ════════════════════════════════════════════════════════
            $loginLogs = $this->entityManager->getRepository(AccessLog::class)
                ->findBy(['user' => $user, 'action' => 'LOGIN'], ['createdAt' => 'DESC'], 5);

            foreach ($loginLogs as $log) {
                $id = 'login_' . $log->getId();
                $ts = $log->getCreatedAt();
                $notifications[] = [
                    'id'       => $id,
                    'category' => 'security',
                    'title'    => 'Connexion détectée',
                    'message'  => 'Connexion depuis ' . ($log->getIpAddress() ?? 'IP inconnue'),
                    'detail'   => 'Navigateur : ' . $this->shortenAgent($log->getUserAgent() ?? ''),
                    'icon'     => 'fas fa-sign-in-alt',
                    'color'    => '#6fbfff',
                    'bg'       => 'rgba(111,191,255,0.12)',
                    'link'     => '/admin/logs',
                    'ts'       => $ts->getTimestamp(),
                    'date'     => $ts->format('d/m/y H:i'),
                    'relative' => $this->relativeTime($ts, $now),
                    'unread'   => ! $isDismissed($id),
                ];
            }

            // ════════════════════════════════════════════════════════
            // 2. TENTATIVES DE CONNEXION ÉCHOUÉES — depuis AccessLog
            // ════════════════════════════════════════════════════════
            $failedLogs = $this->entityManager->getRepository(AccessLog::class)
                ->findBy(['user' => $user, 'action' => 'LOGIN_FAILED'], ['createdAt' => 'DESC'], 10);

            if (count($failedLogs) > 0) {
                // Regrouper les tentatives récentes (dernières 24h)
                $recentFails = array_filter(
                    $failedLogs,
                    fn (AccessLog $l) => $l->getCreatedAt() > new \DateTimeImmutable('-24 hours')
                );
                if (count($recentFails) > 0) {
                    $latest = reset($recentFails);
                    $id = 'login_failed_' . $latest->getId();
                    $ts = $latest->getCreatedAt();
                    $notifications[] = [
                        'id'       => $id,
                        'category' => 'security',
                        'title'    => '⚠️ Tentatives de connexion échouées',
                        'message'  => count($recentFails) . ' tentative(s) échouée(s) dans les dernières 24h',
                        'detail'   => 'Dernière tentative depuis : ' . ($latest->getIpAddress() ?? 'IP inconnue'),
                        'icon'     => 'fas fa-exclamation-triangle',
                        'color'    => '#f87171',
                        'bg'       => 'rgba(248,113,113,0.12)',
                        'link'     => '/admin/logs',
                        'ts'       => $ts->getTimestamp(),
                        'date'     => $ts->format('d/m/y H:i'),
                        'relative' => $this->relativeTime($ts, $now),
                        'unread'   => ! $isDismissed($id),
                    ];
                }
            }

            // ════════════════════════════════════════════════════════
            // 3. LOGOUT — depuis AccessLog
            // ════════════════════════════════════════════════════════
            $logoutLogs = $this->entityManager->getRepository(AccessLog::class)
                ->findBy(['user' => $user, 'action' => 'LOGOUT'], ['createdAt' => 'DESC'], 3);

            foreach ($logoutLogs as $log) {
                $id = 'logout_' . $log->getId();
                $ts = $log->getCreatedAt();
                $notifications[] = [
                    'id'       => $id,
                    'category' => 'security',
                    'title'    => 'Déconnexion',
                    'message'  => 'Session terminée depuis ' . ($log->getIpAddress() ?? 'IP inconnue'),
                    'detail'   => 'Navigateur : ' . $this->shortenAgent($log->getUserAgent() ?? ''),
                    'icon'     => 'fas fa-sign-out-alt',
                    'color'    => '#9ca3af',
                    'bg'       => 'rgba(156,163,175,0.12)',
                    'link'     => '/admin/logs',
                    'ts'       => $ts->getTimestamp(),
                    'date'     => $ts->format('d/m/y H:i'),
                    'relative' => $this->relativeTime($ts, $now),
                    'unread'   => ! $isDismissed($id),
                ];
            }

            // ════════════════════════════════════════════════════════
            // 4. 2FA ACTIVÉ / DÉSACTIVÉ — depuis AccessLog
            // ════════════════════════════════════════════════════════
            $twoFactorLogs = $this->entityManager->getRepository(AccessLog::class)
                ->findBy(['user' => $user, 'action' => '2FA_ENABLED'], ['createdAt' => 'DESC'], 1);

            foreach ($twoFactorLogs as $log) {
                $id = '2fa_enabled_' . $log->getId();
                $ts = $log->getCreatedAt();
                $notifications[] = [
                    'id'       => $id,
                    'category' => 'security',
                    'title'    => '2FA activé',
                    'message'  => 'Double authentification activée sur votre compte',
                    'detail'   => 'Activé le ' . $ts->format('d/m/y à H:i'),
                    'icon'     => 'fas fa-shield-alt',
                    'color'    => '#4dd4ac',
                    'bg'       => 'rgba(77,212,172,0.12)',
                    'link'     => '/settings/security',
                    'ts'       => $ts->getTimestamp(),
                    'date'     => $ts->format('d/m/y H:i'),
                    'relative' => $this->relativeTime($ts, $now),
                    'unread'   => ! $isDismissed($id),
                ];
            }

            $twoFactorDisabledLogs = $this->entityManager->getRepository(AccessLog::class)
                ->findBy(['user' => $user, 'action' => '2FA_DISABLED'], ['createdAt' => 'DESC'], 1);

            foreach ($twoFactorDisabledLogs as $log) {
                $id = '2fa_disabled_' . $log->getId();
                $ts = $log->getCreatedAt();
                $notifications[] = [
                    'id'       => $id,
                    'category' => 'security',
                    'title'    => '🔓 2FA désactivé',
                    'message'  => 'Double authentification désactivée — votre compte est moins protégé',
                    'detail'   => 'Désactivé le ' . $ts->format('d/m/y à H:i'),
                    'icon'     => 'fas fa-shield-alt',
                    'color'    => '#f87171',
                    'bg'       => 'rgba(248,113,113,0.12)',
                    'link'     => '/settings/security',
                    'ts'       => $ts->getTimestamp(),
                    'date'     => $ts->format('d/m/y H:i'),
                    'relative' => $this->relativeTime($ts, $now),
                    'unread'   => ! $isDismissed($id),
                ];
            }

            // ════════════════════════════════════════════════════════
            // 5. CHANGEMENT EMAIL — depuis AccessLog
            // ════════════════════════════════════════════════════════
            $emailChangeLogs = $this->entityManager->getRepository(AccessLog::class)
                ->findBy(['user' => $user, 'action' => 'EMAIL_CHANGED'], ['createdAt' => 'DESC'], 3);

            foreach ($emailChangeLogs as $log) {
                $id = 'email_changed_' . $log->getId();
                $ts = $log->getCreatedAt();
                $notifications[] = [
                    'id'       => $id,
                    'category' => 'security',
                    'title'    => 'Email modifié',
                    'message'  => 'Votre adresse email a été changée',
                    'detail'   => $log->getDetails() ?? ('Modifié le ' . $ts->format('d/m/y à H:i')),
                    'icon'     => 'fas fa-envelope',
                    'color'    => '#6fbfff',
                    'bg'       => 'rgba(111,191,255,0.12)',
                    'link'     => '/settings',
                    'ts'       => $ts->getTimestamp(),
                    'date'     => $ts->format('d/m/y H:i'),
                    'relative' => $this->relativeTime($ts, $now),
                    'unread'   => ! $isDismissed($id),
                ];
            }

            // ════════════════════════════════════════════════════════
            // 6. CHANGEMENT MOT DE PASSE MAÎTRE — depuis AccessLog
            // ════════════════════════════════════════════════════════
            $pwdChangeLogs = $this->entityManager->getRepository(AccessLog::class)
                ->findBy(['user' => $user, 'action' => 'PASSWORD_CHANGED'], ['createdAt' => 'DESC'], 3);

            foreach ($pwdChangeLogs as $log) {
                $id = 'pwd_changed_' . $log->getId();
                $ts = $log->getCreatedAt();
                $notifications[] = [
                    'id'       => $id,
                    'category' => 'security',
                    'title'    => 'Mot de passe maître modifié',
                    'message'  => 'Votre mot de passe maître a été changé',
                    'detail'   => 'Modifié le ' . $ts->format('d/m/y à H:i') . ' depuis ' . ($log->getIpAddress() ?? 'IP inconnue'),
                    'icon'     => 'fas fa-key',
                    'color'    => '#fbbf24',
                    'bg'       => 'rgba(251,191,36,0.12)',
                    'link'     => '/settings/security',
                    'ts'       => $ts->getTimestamp(),
                    'date'     => $ts->format('d/m/y H:i'),
                    'relative' => $this->relativeTime($ts, $now),
                    'unread'   => ! $isDismissed($id),
                ];
            }

            // ════════════════════════════════════════════════════════
            // 7. SECRETS — nouveau (7 derniers jours)
            // ════════════════════════════════════════════════════════
            $recentSecrets = array_filter(
                $this->entityManager->getRepository(Secret::class)
                    ->findBy(['user' => $user, 'deletedAt' => null]),
                fn (Secret $s) => $s->getCreatedAt() > new \DateTimeImmutable('-7 days')
            );

            foreach ($recentSecrets as $s) {
                $id = 'new_secret_' . $s->getId();
                $ts = $s->getCreatedAt();
                $notifications[] = [
                    'id'       => $id,
                    'category' => 'vault',
                    'title'    => 'Nouveau secret ajouté',
                    'message'  => '"' . htmlspecialchars($s->getName()) . '" (' . $this->typeLabel($s->getType()) . ')',
                    'detail'   => 'Secret créé et chiffré avec succès.',
                    'icon'     => 'fas fa-plus-circle',
                    'color'    => '#4dd4ac',
                    'bg'       => 'rgba(77,212,172,0.12)',
                    'link'     => '/vault/',
                    'ts'       => $ts->getTimestamp(),
                    'date'     => $ts->format('d/m/y H:i'),
                    'relative' => $this->relativeTime($ts, $now),
                    'unread'   => ! $isDismissed($id),
                ];
            }



            // ════════════════════════════════════════════════════════
            // 9. SECRETS — anciens (> 90 jours sans mise à jour)
            // ════════════════════════════════════════════════════════
            $oldSecrets = array_filter(
                $this->entityManager->getRepository(Secret::class)
                    ->findBy(['user' => $user, 'deletedAt' => null, 'isArchived' => false]),
                fn (Secret $s) => $s->getCreatedAt() < new \DateTimeImmutable('-90 days')
                    && null === $s->getUpdatedAt()
            );

            if (count($oldSecrets) > 0) {
                $id = 'old_secrets_' . count($oldSecrets);
                $notifications[] = [
                    'id'       => $id,
                    'category' => 'vault',
                    'title'    => 'Secrets anciens',
                    'message'  => count($oldSecrets) . ' secret(s) non mis à jour depuis +90 jours',
                    'detail'   => 'Pensez à vérifier et renouveler vos mots de passe.',
                    'icon'     => 'fas fa-clock',
                    'color'    => '#fbbf24',
                    'bg'       => 'rgba(251,191,36,0.12)',
                    'link'     => '/vault/',
                    'ts'       => $now->getTimestamp() - 90 * 86400,
                    'date'     => (new \DateTimeImmutable('-90 days'))->format('d/m/y'),
                    'relative' => 'Il y a +90 jours',
                    'unread'   => ! $isDismissed($id),
                ];
            }

            // ════════════════════════════════════════════════════════
            // 10. CORBEILLE non vidée
            // ════════════════════════════════════════════════════════
            $trashedSecrets = $this->entityManager->getRepository(Secret::class)
                ->createQueryBuilder('s')
                ->where('s.user = :user')
                ->andWhere('s.deletedAt IS NOT NULL')
                ->setParameter('user', $user)
                ->getQuery()->getResult();

            if (count($trashedSecrets) > 0) {
                $oldest = null;
                foreach ($trashedSecrets as $s) {
                    if (null === $oldest || $s->getDeletedAt() < $oldest) {
                        $oldest = $s->getDeletedAt();
                    }
                }
                $id = 'trash_' . count($trashedSecrets);
                $notifications[] = [
                    'id'       => $id,
                    'category' => 'vault',
                    'title'    => 'Corbeille non vidée',
                    'message'  => count($trashedSecrets) . ' secret(s) dans la corbeille',
                    'detail'   => 'Cliquez pour accéder à la corbeille et les supprimer définitivement.',
                    'icon'     => 'fas fa-trash',
                    'color'    => '#f97316',
                    'bg'       => 'rgba(249,115,22,0.12)',
                    'link'     => '/vault/?bin=1',
                    'ts'       => $oldest->getTimestamp(),
                    'date'     => $oldest->format('d/m/y H:i'),
                    'relative' => $this->relativeTime($oldest, $now),
                    'unread'   => ! $isDismissed($id),
                ];
            }

            // ════════════════════════════════════════════════════════
            // 11. IMPORT effectué — depuis AccessLog
            // ════════════════════════════════════════════════════════
            $importLogs = $this->entityManager->getRepository(AccessLog::class)
                ->findBy(['user' => $user, 'action' => 'IMPORT'], ['createdAt' => 'DESC'], 3);

            foreach ($importLogs as $log) {
                $id = 'import_' . $log->getId();
                $ts = $log->getCreatedAt();
                $notifications[] = [
                    'id'       => $id,
                    'category' => 'vault',
                    'title'    => 'Import effectué',
                    'message'  => $log->getDetails() ?? 'Secrets importés avec succès',
                    'detail'   => 'Import le ' . $ts->format('d/m/y à H:i'),
                    'icon'     => 'fas fa-file-import',
                    'color'    => '#c084fc',
                    'bg'       => 'rgba(192,132,252,0.12)',
                    'link'     => '/vault/',
                    'ts'       => $ts->getTimestamp(),
                    'date'     => $ts->format('d/m/y H:i'),
                    'relative' => $this->relativeTime($ts, $now),
                    'unread'   => ! $isDismissed($id),
                ];
            }

            // ════════════════════════════════════════════════════════
            // 12. EXPORT effectué — depuis AccessLog
            // ════════════════════════════════════════════════════════
            $exportLogs = $this->entityManager->getRepository(AccessLog::class)
                ->findBy(['user' => $user, 'action' => 'EXPORT'], ['createdAt' => 'DESC'], 3);

            foreach ($exportLogs as $log) {
                $id = 'export_' . $log->getId();
                $ts = $log->getCreatedAt();
                $notifications[] = [
                    'id'       => $id,
                    'category' => 'vault',
                    'title'    => 'Export effectué',
                    'message'  => $log->getDetails() ?? 'Données exportées',
                    'detail'   => 'Export le ' . $ts->format('d/m/y à H:i'),
                    'icon'     => 'fas fa-file-export',
                    'color'    => '#c084fc',
                    'bg'       => 'rgba(192,132,252,0.12)',
                    'link'     => '/vault/',
                    'ts'       => $ts->getTimestamp(),
                    'date'     => $ts->format('d/m/y H:i'),
                    'relative' => $this->relativeTime($ts, $now),
                    'unread'   => ! $isDismissed($id),
                ];
            }

            // ════════════════════════════════════════════════════════
            // 13. AUCUNE COLLECTION
            // ════════════════════════════════════════════════════════
            if (0 === count($user->getCollections())) {
                $id = 'no_collections';
                $notifications[] = [
                    'id'       => $id,
                    'category' => 'vault',
                    'title'    => 'Aucune collection',
                    'message'  => 'Organisez vos secrets en créant votre première collection',
                    'detail'   => 'Les collections permettent de regrouper vos secrets par projet ou usage.',
                    'icon'     => 'fas fa-layer-group',
                    'color'    => '#c084fc',
                    'bg'       => 'rgba(192,132,252,0.12)',
                    'link'     => '/collections/new',
                    'ts'       => $now->getTimestamp() - 86400,
                    'date'     => $now->format('d/m/y H:i'),
                    'relative' => 'Conseil',
                    'unread'   => ! $isDismissed($id),
                ];
            }

            // ════════════════════════════════════════════════════════
            // 14. ADMIN — changements AppSettings (admin seulement)
            // ════════════════════════════════════════════════════════
            if ($this->isGranted('ROLE_ADMIN')) {
                $settingsLogs = $this->entityManager->getRepository(AccessLog::class)
                    ->findBy(['action' => 'ADMIN_SETTINGS_CHANGED'], ['createdAt' => 'DESC'], 5);

                foreach ($settingsLogs as $log) {
                    $id = 'admin_settings_' . $log->getId();
                    $ts = $log->getCreatedAt();
                    $notifications[] = [
                        'id'       => $id,
                        'category' => 'admin',
                        'title'    => '⚙️ Paramètres app modifiés',
                        'message'  => $log->getDetails() ?? 'Configuration de l\'application modifiée',
                        'detail'   => 'Par ' . ($log->getUser()?->getEmail() ?? 'admin') . ' le ' . $ts->format('d/m/y à H:i'),
                        'icon'     => 'fas fa-sliders-h',
                        'color'    => '#fbbf24',
                        'bg'       => 'rgba(251,191,36,0.12)',
                        'link'     => '/admin',
                        'ts'       => $ts->getTimestamp(),
                        'date'     => $ts->format('d/m/y H:i'),
                        'relative' => $this->relativeTime($ts, $now),
                        'unread'   => ! $isDismissed($id),
                    ];
                }

                $newUserLogs = $this->entityManager->getRepository(AccessLog::class)
                    ->findBy(['action' => 'USER_REGISTERED'], ['createdAt' => 'DESC'], 5);

                foreach ($newUserLogs as $log) {
                    $id = 'new_user_' . $log->getId();
                    $ts = $log->getCreatedAt();
                    $notifications[] = [
                        'id'       => $id,
                        'category' => 'admin',
                        'title'    => 'Nouvel utilisateur inscrit',
                        'message'  => $log->getDetails() ?? 'Un nouveau compte a été créé',
                        'detail'   => 'Inscrit le ' . $ts->format('d/m/y à H:i'),
                        'icon'     => 'fas fa-user-plus',
                        'color'    => '#4dd4ac',
                        'bg'       => 'rgba(77,212,172,0.12)',
                        'link'     => '/admin',
                        'ts'       => $ts->getTimestamp(),
                        'date'     => $ts->format('d/m/y H:i'),
                        'relative' => $this->relativeTime($ts, $now),
                        'unread'   => ! $isDismissed($id),
                    ];
                }
            }

            // ════════════════════════════════════════════════════════
            // SORT + COUNT
            // ════════════════════════════════════════════════════════
            usort($notifications, fn ($a, $b) => $b['ts'] - $a['ts']);
            $unreadCount = count(array_filter($notifications, fn ($n) => $n['unread']));

            return new JsonResponse([
                'count'         => $unreadCount,
                'total'         => count($notifications),
                'notifications' => $notifications,
            ]);
        } catch (\Throwable $e) {
            return new JsonResponse([
                'error' => $e->getMessage(),
                'file'  => $e->getFile(),
                'line'  => $e->getLine(),
            ], 500);
        }
    }

    // ════════════════════════════════════════════════════════
    // MARK READ — utilise UserNotificationDismissal en DB
    // ════════════════════════════════════════════════════════
    #[Route('/notifications/mark-read', name: 'app_notifications_mark_read', methods: ['POST'])]
    public function markAllRead(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $this->getUser();

        $ids = $request->request->all('ids');

        foreach ($ids as $id) {
            $this->dismissalRepo->dismiss($user, (string) $id);
        }

        return new JsonResponse(['ok' => true]);
    }

    #[Route('/notifications/mark-one-read', name: 'app_notifications_mark_one_read', methods: ['POST'])]
    public function markOneRead(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $this->getUser();
        $id = $request->request->get('id', '');
        if ($id) {
            $this->dismissalRepo->dismiss($user, $id);
        }

        return new JsonResponse(['ok' => true]);
    }

    // ════════════════════════════════════════════════════════
    // HELPERS PRIVÉS
    // ════════════════════════════════════════════════════════
    private function relativeTime(\DateTimeImmutable $dt, \DateTimeImmutable $now): string
    {
        $diff = $now->getTimestamp() - $dt->getTimestamp();
        if ($diff < 60) {
            return 'À l\'instant';
        }
        if ($diff < 3600) {
            return 'Il y a ' . floor($diff / 60) . ' min';
        }
        if ($diff < 86400) {
            return 'Il y a ' . floor($diff / 3600) . ' h';
        }
        if ($diff < 604800) {
            return 'Il y a ' . floor($diff / 86400) . ' jour(s)';
        }

        return $dt->format('d/m/y H:i');
    }

    private function shortenAgent(string $ua): string
    {
        if (str_contains($ua, 'Chrome')) {
            return 'Chrome';
        }
        if (str_contains($ua, 'Firefox')) {
            return 'Firefox';
        }
        if (str_contains($ua, 'Safari')) {
            return 'Safari';
        }
        if (str_contains($ua, 'Edge')) {
            return 'Edge';
        }

        return substr($ua, 0, 40) ?: 'Inconnu';
    }

    private function typeLabel(string $type): string
    {
        return match($type) {
            'password' => 'Mot de passe', // pragma: allowlist secret
            'api_key'  => 'Clé API', // pragma: allowlist secret
            'note'     => 'Note sécurisée',
            'identity' => 'Identité',
            default    => $type,
        };
    }

    /*
     * Score de force du mot de passe 0–100.
     * Même logique que le frontend JS pour cohérence.
     */

}
