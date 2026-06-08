<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\AccessLog;
use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[IsGranted('ROLE_ADMIN')]
#[Route('/admin')]
class AdminController extends AbstractController
{
    public function __construct(
        private EntityManagerInterface $entityManager
    ) {
    }

    #[Route('/', name: 'app_admin_index')]
    public function index(): Response
    {
        $users = $this->entityManager->getRepository(User::class)->findAll();
        $logs  = $this->entityManager->getRepository(AccessLog::class)
                      ->findBy([], ['createdAt' => 'DESC'], 20);

        return $this->render('admin/index.html.twig', [
            'users' => $users,
            'logs'  => $logs,
        ]);
    }

    #[Route('/user/{id}/toggle', name: 'app_admin_toggle_user', methods: ['POST'])]
    public function toggleUser(User $user, Request $request): Response
    {
        if ($this->isCsrfTokenValid('toggle' . $user->getId(), $request->request->get('_token'))) {
            $user->setIsActive(! $user->getIsActive());
            $this->entityManager->flush();
            $status = $user->getIsActive() ? 'activé' : 'désactivé';
            $this->addFlash('success', "Utilisateur {$status} avec succès !");
        }

        return $this->redirectToRoute('app_admin_index');
    }

    #[Route('/logs', name: 'app_admin_logs')]
    public function logs(): Response
    {
        $logs = $this->entityManager->getRepository(AccessLog::class)
                     ->findBy([], ['createdAt' => 'DESC'], 100);

        return $this->render('admin/logs.html.twig', [
            'logs' => $logs,
        ]);
    }
}
