<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Form\RegistrationFormType;
use App\Service\EmailVerificationService;
use App\Service\EncryptionService;
use App\Trait\LogsActionTrait;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
// AJOUTÉ : Importations requises en haut du fichier
use Symfony\Component\Routing\Attribute\Route;

class RegistrationController extends AbstractController
{
    // AJOUTÉ : Utilisation du trait dans la classe
    use LogsActionTrait;

    // MODIFIÉ : Ajout de l'EntityManagerInterface dans le constructeur
    public function __construct(
        private EncryptionService $encryptionService,
        private EmailVerificationService $emailVerificationService,
        private EntityManagerInterface $entityManager
    ) {
    }

    #[Route('/register', name: 'app_register')]
    public function register(
        Request $request,
        UserPasswordHasherInterface $userPasswordHasher,
        EntityManagerInterface $entityManager
    ): Response {
        $user = new User();
        $form = $this->createForm(RegistrationFormType::class, $user);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $plainPassword = $form->get('plainPassword')->getData();

            // Hash du mot de passe
            $user->setPassword(
                $userPasswordHasher->hashPassword($user, $plainPassword)
            );

            // Génération du sel de chiffrement
            $salt = $this->encryptionService->generateSalt();
            $user->setEncryptionKeySalt($salt);

            // Chiffrement de la réponse de sécurité
            $plainAnswer = $form->get('securityAnswer')->getData();
            $encrypted = $this->encryptionService->encryptWithAppSecret(
                $plainAnswer,
                $this->getParameter('kernel.secret')
            );
            $user->setSecurityAnswerEncrypted($encrypted['encrypted']);
            $user->setSecurityAnswerIv($encrypted['iv']);

            // Valeurs par défaut
            $user->setRoles(['ROLE_USER']);
            $user->setIsActive(true);
            $user->setIsVerified(false);
            $user->setCreatedAt(new \DateTimeImmutable());

            // Token de vérification
            $this->emailVerificationService->setVerificationToken($user);

            $entityManager->persist($user);
            $entityManager->flush();

            // AJOUTÉ : Log de l'action juste après le flush() de l'EntityManager
            $this->logAction($user, 'USER_REGISTERED', $request, 'Nouveau compte créé : ' . $user->getEmail());

            // Envoyer l'email de vérification
            $this->emailVerificationService->sendVerificationEmail($user);

            $this->addFlash('success', 'Un email de vérification a été envoyé à ' . $user->getEmail() . '. Veuillez confirmer votre adresse avant de vous connecter.');

            return $this->redirectToRoute('app_login');
        }

        return $this->render('registration/register.html.twig', [
            'registrationForm' => $form,
        ]);
    }
}
