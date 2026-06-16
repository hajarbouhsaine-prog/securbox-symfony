<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[IsGranted('ROLE_USER')]
class VaultLockController extends AbstractController
{
    #[Route('/vault/unlock', name: 'app_vault_unlock', methods: ['POST'])]
    public function unlock(Request $request, UserPasswordHasherInterface $hasher): JsonResponse
    {
        $user     = $this->getUser();
        $password = (string) $request->request->get('master_password', '');

        if ('' === $password) {
            return new JsonResponse(['ok' => false, 'error' => 'Mot de passe requis.'], 400);
        }

        if (! $hasher->isPasswordValid($user, $password)) {
            return new JsonResponse(['ok' => false, 'error' => 'Mot de passe incorrect.'], 401);
        }

        // Restore the master password in session so encryption/decryption works
        // again after the vault was locked.
        $session = $request->getSession();
        $session->set('vault_master_password', $password);
        $session->set('vault_last_activity', time());
        $session->set('vault_locked', false);

        return new JsonResponse(['ok' => true]);
    }

    #[Route('/vault/lock', name: 'app_vault_lock', methods: ['POST'])]
    public function lock(Request $request): JsonResponse
    {
        $session = $request->getSession();
        $session->set('vault_locked', true);
        // Remove the master password from session when the vault is locked so it
        // cannot be used until the user unlocks again.
        $session->remove('vault_master_password');

        return new JsonResponse(['ok' => true]);
    }
}
