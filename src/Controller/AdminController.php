<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\AccessLog;
use App\Entity\User;
use App\Trait\LogsActionTrait;
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
    use LogsActionTrait;

    public function __construct(
        private EntityManagerInterface $entityManager
    ) {
    }

    #[Route('/', name: 'app_admin_index')]
    public function index(): Response
    {
        $users = $this->entityManager->getRepository(User::class)->findAll();
        $logs  = $this->entityManager->getRepository(AccessLog::class)
                      ->findBy([], ['createdAt' => 'DESC'], 10);

        return $this->render('admin/index.html.twig', [
            'users' => $users,
            'logs'  => $logs,
        ]);
    }

    #[Route('/user/{id}/toggle', name: 'app_admin_toggle_user', methods: ['POST'])]
    public function toggleUser(User $user, Request $request): Response
    {
        /** @var User $admin */
        $admin = $this->getUser();

        if ($user === $admin) {
            $this->addFlash('error', 'Vous ne pouvez pas désactiver votre propre compte.');

            return $this->redirectToRoute('app_admin_index');
        }

        if ($this->isCsrfTokenValid('toggle' . $user->getId(), $request->request->get('_token'))) {
            $user->setIsActive(! $user->getIsActive());
            $this->entityManager->flush();
            $status = $user->getIsActive() ? 'activé' : 'désactivé';
            $this->logAction(
                $admin,
                'ADMIN_TOGGLE_USER',
                $request,
                "Utilisateur {$user->getEmail()} {$status}"
            );
            $this->addFlash('success', "Utilisateur {$status} avec succès !");
        }

        return $this->redirectToRoute('app_admin_index');
    }

    #[Route('/user/{id}/delete', name: 'app_admin_delete_user', methods: ['POST'])]
    public function deleteUser(User $user, Request $request): Response
    {
        /** @var User $admin */
        $admin = $this->getUser();

        if ($user === $admin) {
            $this->addFlash('error', 'Vous ne pouvez pas supprimer votre propre compte.');

            return $this->redirectToRoute('app_admin_index');
        }

        if (in_array('ROLE_ADMIN', $user->getRoles(), true)) {
            $this->addFlash('error', 'Impossible de supprimer un autre administrateur.');

            return $this->redirectToRoute('app_admin_index');
        }

        if ($this->isCsrfTokenValid('delete_user_' . $user->getId(), $request->request->get('_token'))) {
            $email = $user->getEmail();
            $this->entityManager->remove($user);
            $this->entityManager->flush();
            $this->logAction(
                $admin,
                'ADMIN_DELETE_USER',
                $request,
                "Compte supprimé : {$email}"
            );
            $this->addFlash('success', "Compte \"{$email}\" supprimé définitivement.");
        }

        return $this->redirectToRoute('app_admin_index');
    }

    #[Route('/logs', name: 'app_admin_logs')]
    public function logs(): Response
    {
        $logs = $this->entityManager->getRepository(AccessLog::class)
                     ->findBy([], ['createdAt' => 'DESC'], 200);

        return $this->render('admin/logs.html.twig', [
            'logs' => $logs,
        ]);
    }
}
