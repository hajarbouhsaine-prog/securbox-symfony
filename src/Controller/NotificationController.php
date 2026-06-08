<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\Secret;
use App\Entity\User;
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
        private EntityManagerInterface $entityManager
    ) {
    }

    #[Route('/notifications', name: 'app_notifications', methods: ['GET'])]
    public function index(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $this->getUser();
        $notifications = [];

        $secrets = $this->entityManager->getRepository(Secret::class)
            ->findBy(['user' => $user, 'deletedAt' => null]);

        // 1. Items in trash
        $trashed = $this->entityManager->getRepository(Secret::class)
            ->findBy(['user' => $user]);
        $trashedCount = count(array_filter($trashed, fn($s) => $s->getDeletedAt() !== null));
        if ($trashedCount > 0) {
            $notifications[] = [
                'title'   => 'Corbeille non vidée',
                'message' => $trashedCount . ' élément(s) dans la corbeille depuis plus de 7 jours.',
                'icon'    => 'fas fa-trash',
                'color'   => '#f97316',
                'bg'      => 'rgba(249,115,22,0.12)',
            ];
        }

        // 2. Recently added secrets (last 7 days)
        $recentCount = count(array_filter($secrets, function (Secret $s) {
            return $s->getCreatedAt() > new \DateTimeImmutable('-7 days');
        }));
        if ($recentCount > 0) {
            $notifications[] = [
                'title'   => 'Nouveaux secrets',
                'message' => $recentCount . ' secret(s) ajouté(s) ces 7 derniers jours.',
                'icon'    => 'fas fa-plus-circle',
                'color'   => '#4dd4ac',
                'bg'      => 'rgba(77,212,172,0.12)',
            ];
        }

        // 3. Old secrets (not updated in 90 days)
        $oldCount = count(array_filter($secrets, function (Secret $s) {
            return $s->getCreatedAt() < new \DateTimeImmutable('-90 days');
        }));
        if ($oldCount > 0) {
            $notifications[] = [
                'title'   => 'Secrets anciens',
                'message' => $oldCount . ' secret(s) n\'ont pas été mis à jour depuis 90 jours.',
                'icon'    => 'fas fa-clock',
                'color'   => '#fbbf24',
                'bg'      => 'rgba(251,191,36,0.12)',
            ];
        }

        // 4. No collections
        if (count($user->getCollections()) === 0) {
            $notifications[] = [
                'title'   => 'Aucune collection',
                'message' => 'Organisez vos secrets en créant une collection.',
                'icon'    => 'fas fa-layer-group',
                'color'   => '#6fbfff',
                'bg'      => 'rgba(111,191,255,0.12)',
            ];
        }

        return new JsonResponse([
            'count'         => count($notifications),
            'notifications' => $notifications,
        ]);
    }
}