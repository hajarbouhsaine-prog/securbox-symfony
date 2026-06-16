<?php

declare(strict_types=1);

namespace App\Controller;

use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class VerifyEmailController extends AbstractController
{
    #[Route('/verify/email/{token}', name: 'app_verify_email')]
    public function verifyEmail(
        string $token,
        UserRepository $userRepository,
        EntityManagerInterface $entityManager
    ): Response {
        $user = $userRepository->findOneBy(['verificationToken' => $token]);

        if (! $user) {
            $this->addFlash('error', '❌ Lien de vérification invalide ou expiré.');

            return $this->redirectToRoute('app_login');
        }

        $user->setIsVerified(true);
        $user->setVerificationToken(null);
        $entityManager->flush();

        $this->addFlash('success', '✅ Votre email a été vérifié avec succès ! Vous pouvez maintenant vous connecter.');

        return $this->redirectToRoute('app_login');
    }
}
