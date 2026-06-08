<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\AccessLog;
use App\Entity\Secret;
use App\Repository\CollectionRepository;
use App\Service\EncryptionService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[IsGranted('ROLE_USER')]
#[Route('/vault')]
class VaultController extends AbstractController
{
    public function __construct(
        private EncryptionService $encryptionService,
        private EntityManagerInterface $entityManager,
        private CollectionRepository $collectionRepository
    ) {
    }

    #[Route('/', name: 'app_vault_index')]
    public function index(Request $request): Response
    {
        /** @var \App\Entity\User $user */
        $user = $this->getUser();
        $type         = $request->query->get('type');
        $collectionId = $request->query->get('collection');
        $favorite     = $request->query->get('favorite');
        $archived     = $request->query->get('archived');
        $bin          = $request->query->get('bin');

        $qb = $this->entityManager->getRepository(Secret::class)
            ->createQueryBuilder('s')
            ->where('s.user = :user')
            ->setParameter('user', $user);

        if ($bin) {
            // Corbeille — show only soft-deleted
            $qb->andWhere('s.deletedAt IS NOT NULL');
        } else {
            // Normal view — never show deleted items
            $qb->andWhere('s.deletedAt IS NULL');

            if ($archived) {
                $qb->andWhere('s.isArchived = true');
            } else {
                // Normal view — don't show archived
                $qb->andWhere('s.isArchived = false');

                if ($favorite) {
                    $qb->andWhere('s.isFavorite = true');
                }
                if ($type) {
                    $qb->andWhere('s.type = :type')->setParameter('type', $type);
                }
                if ($collectionId) {
                    $qb->andWhere('s.collection = :col')->setParameter('col', $collectionId);
                }
            }
        }

        $secrets     = $qb->getQuery()->getResult();
        $collections = $this->collectionRepository->findByUser($user);

        return $this->render('vault/index.html.twig', [
            'secrets'     => $secrets,
            'collections' => $collections,
        ]);
    }

    #[Route('/new', name: 'app_vault_new', methods: ['GET', 'POST'])]
    public function new(Request $request): Response
    {
        /** @var \App\Entity\User $user */
        $user = $this->getUser();
        $validTypes = ['password', 'api_key', 'identity', 'note'];
        $defaultType = $request->query->get('type', 'password');
        if (! in_array($defaultType, $validTypes, true)) {
            $defaultType = 'password';
        }

        if ($request->isMethod('POST')) {
            $masterPassword = (string) $request->request->get('master_password', '');
            $name           = trim((string) $request->request->get('name', ''));
            $type           = (string) $request->request->get('type', $defaultType);
            $data           = (string) $request->request->get('data', '');

            if (! $this->isCsrfTokenValid('new_secret', $request->request->get('_token'))) {
                $this->addFlash('error', 'Action refusée : jeton de sécurité invalide.');

                return $this->render('vault/new.html.twig', [
                    'defaultType' => $defaultType,
                    'collections' => $this->collectionRepository->findByUser($user),
                ]);
            }

            if ('' === $masterPassword) {
                $this->addFlash('error', 'Erreur : le mot de passe maître est requis pour chiffrer le secret.');

                return $this->render('vault/new.html.twig', [
                    'defaultType' => $defaultType,
                    'collections' => $this->collectionRepository->findByUser($user),
                ]);
            }

            if ('' === $name || ! in_array($type, $validTypes, true)) {
                $this->addFlash('error', 'Veuillez renseigner un nom et un type de secret valide.');

                return $this->render('vault/new.html.twig', [
                    'defaultType' => $defaultType,
                    'collections' => $this->collectionRepository->findByUser($user),
                ]);
            }

            $collection = null;
            $collectionId = $request->request->get('collection_id');
            if ($collectionId) {
                $collection = $this->collectionRepository->find($collectionId);
            }

            if (! $collection || $collection->getUser() !== $user) {
                $this->addFlash('error', 'Veuillez sélectionner une collection valide.');

                return $this->render('vault/new.html.twig', [
                    'defaultType' => $type,
                    'collections' => $this->collectionRepository->findByUser($user),
                ]);
            }

            $key = $this->encryptionService->deriveKey(
                $masterPassword,
                $user->getEncryptionKeySalt()
            );

            $encrypted = $this->encryptionService->encrypt($data, $key);

            $secret = new Secret();
            $secret->setUser($user);
            $secret->setName($name);
            $secret->setType($type);
            $secret->setEncryptedData($encrypted['encrypted']);
            $secret->setIv($encrypted['iv']);
            $secret->setCreatedAt(new \DateTimeImmutable());
            $secret->setCollection($collection);

            $this->entityManager->persist($secret);
            $this->logAction('CREATE', $secret, $request);
            $this->entityManager->flush();

            $this->addFlash('success', 'Secret ajouté avec succès !');

            return $this->redirectToRoute('app_vault_index');
        }

        return $this->render('vault/new.html.twig', [
            'defaultType' => $defaultType,
            'collections' => $this->collectionRepository->findByUser($user),
        ]);
    }

    #[Route('/{id}/show', name: 'app_vault_show', methods: ['GET', 'POST'])]
    public function show(Secret $secret, Request $request): Response
    {
        if ($secret->getUser() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        $decryptedData = null;
        $decryptedPayload = null;

        if ($request->isMethod('POST')) {
            $masterPassword = (string) $request->request->get('master_password', '');
            /** @var \App\Entity\User $user */
            $user = $this->getUser();

            if ('' === $masterPassword) {
                $this->addFlash('error', 'Mot de passe maître requis !');

                return $this->render($request->query->get('modal') ? 'vault/_show_partial.html.twig' : 'vault/show.html.twig', [
                    'secret'           => $secret,
                    'decryptedData'    => $decryptedData,
                    'decryptedPayload' => $decryptedPayload,
                ]);
            }

            $key = $this->encryptionService->deriveKey(
                $masterPassword,
                $user->getEncryptionKeySalt()
            );

            try {
                $decryptedData = $this->encryptionService->decrypt(
                    $secret->getEncryptedData(),
                    $secret->getIv(),
                    $key
                );
                $decryptedPayload = json_decode($decryptedData, true);
                if (JSON_ERROR_NONE !== json_last_error()) {
                    $decryptedPayload = null;
                }
                $this->logAction('VIEW', $secret, $request);
                $this->entityManager->flush();
            } catch (\RuntimeException $e) {
                $this->addFlash('error', 'Mot de passe maître incorrect !');
            }
        }

        // If requested as a modal (AJAX/modal fetch), render a partial fragment
        if ($request->query->get('modal')) {
            return $this->render('vault/_show_partial.html.twig', [
                'secret'           => $secret,
                'decryptedData'    => $decryptedData,
                'decryptedPayload' => $decryptedPayload,
            ]);
        }

        return $this->render('vault/show.html.twig', [
            'secret'           => $secret,
            'decryptedData'    => $decryptedData,
            'decryptedPayload' => $decryptedPayload,
        ]);
    }

    #[Route('/{id}/edit', name: 'app_vault_edit', methods: ['GET', 'POST'])]
    public function edit(Secret $secret, Request $request): Response
    {
        if ($secret->getUser() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        /** @var \App\Entity\User $user */
        $user = $this->getUser();
        $decryptedData = null;
        $step = 'verify';

        if ($request->isMethod('POST')) {
            $masterPassword = (string) $request->request->get('master_password', '');

            if (! $this->isCsrfTokenValid('edit' . $secret->getId(), $request->request->get('_token'))) {
                $this->addFlash('error', 'Action refusée : jeton de sécurité invalide.');

                return $this->render('vault/edit.html.twig', [
                    'secret'        => $secret,
                    'decryptedData' => $decryptedData,
                    'step'          => $step,
                ]);
            }

            if ('' === $masterPassword) {
                $this->addFlash('error', 'Mot de passe maître requis !');

                return $this->render('vault/edit.html.twig', [
                    'secret'        => $secret,
                    'decryptedData' => $decryptedData,
                    'step'          => $step,
                ]);
            }

            $key = $this->encryptionService->deriveKey(
                $masterPassword,
                $user->getEncryptionKeySalt()
            );

            // Étape de traitement après modification
            if ($request->request->has('update_secret')) {
                try {
                    $name = $request->request->get('name');

                    // Reconstruction dynamique de la donnée suivant le type
                    if ('password' === $secret->getType()) {
                        $payload = [
                            'type'     => 'password',
                            'username' => $request->request->get('username', ''),
                            'password' => $request->request->get('password', ''),
                            'website'  => $request->request->get('website', ''),
                        ];
                        $dataToEncrypt = json_encode($payload);
                    } else {
                        $dataToEncrypt = $request->request->get('data', '');
                    }

                    // Ré-chiffrement
                    $encrypted = $this->encryptionService->encrypt($dataToEncrypt, $key);

                    $secret->setName($name);
                    $secret->setEncryptedData($encrypted['encrypted']);
                    $secret->setIv($encrypted['iv']);

                    $this->logAction('UPDATE', $secret, $request);
                    $this->entityManager->flush();

                    $this->addFlash('success', 'Secret modifié avec succès !');

                    return $this->redirectToRoute('app_vault_index');
                } catch (\RuntimeException $e) {
                    $this->addFlash('error', 'Session expirée ou clé invalide. Veuillez réessayer.');
                }
            } else {
                // Étape de déchiffrement initial
                try {
                    $decryptedData = $this->encryptionService->decrypt(
                        $secret->getEncryptedData(),
                        $secret->getIv(),
                        $key
                    );
                    $step = 'edit';
                } catch (\RuntimeException $e) {
                    $this->addFlash('error', 'Mot de passe maître incorrect !');
                }
            }
        }

        return $this->render('vault/edit.html.twig', [
            'secret'        => $secret,
            'decryptedData' => $decryptedData,
            'step'          => $step,
        ]);
    }

    #[Route('/{id}/delete', name: 'app_vault_delete', methods: ['POST'])]
    public function delete(Secret $secret, Request $request): Response
    {
        if ($secret->getUser() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        if (! $this->isCsrfTokenValid('delete' . $secret->getId(), $request->request->get('_token'))) {
            $this->addFlash('error', 'Action refusée : jeton de sécurité invalide.');

            return $this->redirectToRoute('app_vault_index');
        }

        // Access logs are linked to the secret, so remove them before hard delete.
        $accessLogRepository = $this->entityManager->getRepository(AccessLog::class);
        $logs = $accessLogRepository->findBy(['secret' => $secret]);
        foreach ($logs as $log) {
            $this->entityManager->remove($log);
        }

        $this->entityManager->remove($secret);
        $this->entityManager->flush();
        $this->addFlash('success', 'Secret supprimé avec succès !');

        return $this->redirectToRoute('app_vault_index');
    }

    #[Route('/{id}/favorite', name: 'app_vault_favorite', methods: ['POST'])]
    public function toggleFavorite(Secret $secret, Request $request): Response
    {
        if ($secret->getUser() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        if (! $this->isCsrfTokenValid('favorite' . $secret->getId(), $request->request->get('_token'))) {
            $this->addFlash('error', 'Action refusée : jeton de sécurité invalide.');

            return $this->redirectToRoute('app_vault_index');
        }

        $secret->setIsFavorite(! $secret->isFavorite());
        $this->entityManager->flush();
        $this->addFlash('success', $secret->isFavorite() ? 'Ajouté aux favoris !' : 'Retiré des favoris !');

        return $this->redirectToRoute('app_vault_index');
    }

    #[Route('/{id}/archive', name: 'app_vault_archive', methods: ['POST'])]
    public function toggleArchive(Secret $secret, Request $request): Response
    {
        if ($secret->getUser() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        if (! $this->isCsrfTokenValid('archive' . $secret->getId(), $request->request->get('_token'))) {
            $this->addFlash('error', 'Action refusée : jeton de sécurité invalide.');

            return $this->redirectToRoute('app_vault_index');
        }

        $secret->setIsArchived(! $secret->isArchived());
        $this->entityManager->flush();
        $this->addFlash('success', $secret->isArchived() ? 'Secret archivé !' : 'Secret restauré !');

        return $this->redirectToRoute('app_vault_index');
    }

    #[Route('/{id}/trash', name: 'app_vault_trash', methods: ['POST'])]
    public function moveToTrash(Secret $secret, Request $request): Response
    {
        if ($secret->getUser() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        if (! $this->isCsrfTokenValid('trash' . $secret->getId(), $request->request->get('_token'))) {
            $this->addFlash('error', 'Action refusée : jeton de sécurité invalide.');

            return $this->redirectToRoute('app_vault_index');
        }

        $secret->setDeletedAt(new \DateTimeImmutable());
        $this->entityManager->flush();
        $this->addFlash('success', 'Secret déplacé vers la corbeille.');

        return $this->redirectToRoute('app_vault_index');
    }

    #[Route('/{id}/restore', name: 'app_vault_restore', methods: ['POST'])]
    public function restore(Secret $secret, Request $request): Response
    {
        if ($secret->getUser() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        if (! $this->isCsrfTokenValid('restore' . $secret->getId(), $request->request->get('_token'))) {
            $this->addFlash('error', 'Action refusée : jeton de sécurité invalide.');

            return $this->redirectToRoute('app_vault_index', ['bin' => 1]);
        }

        $secret->setDeletedAt(null);
        $this->entityManager->flush();
        $this->addFlash('success', 'Secret restauré !');

        return $this->redirectToRoute('app_vault_index', ['bin' => 1]);
    }

    private function logAction(string $action, Secret $secret, Request $request): void
    {
        /** @var \App\Entity\User $user */
        $user = $this->getUser();

        $log = new AccessLog();
        $log->setUser($user);
        $log->setSecret($secret);
        $log->setAction($action);
        $log->setIpAddress($request->getClientIp() ?? '0.0.0.0');
        $log->setUserAgent($request->headers->get('User-Agent') ?? '');
        $log->setCreatedAt(new \DateTimeImmutable());
        $this->entityManager->persist($log);
    }
}
