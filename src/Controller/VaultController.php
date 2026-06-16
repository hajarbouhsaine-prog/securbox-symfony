<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\AccessLog;
use App\Entity\Secret;
use App\Repository\CollectionRepository;
use App\Service\EncryptionService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\ResponseHeaderBag;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[IsGranted('ROLE_USER')]
#[Route('/vault')]
class VaultController extends AbstractController
{
    public function __construct(
        private EncryptionService $encryptionService,
        private EntityManagerInterface $entityManager,
        private CollectionRepository $collectionRepository,
    ) {
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Helper — get the master password from the session.
    // ─────────────────────────────────────────────────────────────────────────
    private function getMasterPasswordFromSession(Request $request): ?string
    {
        $session = $request->getSession();
        $locked  = (bool) $session->get('vault_locked', false);
        if ($locked) {
            return null;
        }
        $pwd = $session->get('vault_master_password', '');

        return ('' !== $pwd) ? $pwd : null;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  Helper — save uploaded files to disk, return metadata array only.
    // ─────────────────────────────────────────────────────────────────────────
    private function handleFileUploads(Request $request): array
    {
        /** @var string $attachmentsDir */
        $attachmentsDir = (string) $this->getParameter('attachments_directory');

        if (! is_dir($attachmentsDir)) {
            mkdir($attachmentsDir, 0755, true);
        }

        $attachmentsMeta = [];

        /** @var UploadedFile[]|null $uploadedFiles */
        $uploadedFiles = $request->files->get('attachments');
        if (empty($uploadedFiles)) {
            return [];
        }

        if (! is_array($uploadedFiles)) {
            $uploadedFiles = [$uploadedFiles];
        }

        foreach ($uploadedFiles as $file) {
            if (! $file instanceof UploadedFile || ! $file->isValid()) {
                continue;
            }

            if ($file->getSize() > 50 * 1024 * 1024) {
                continue;
            }

            $originalName = $file->getClientOriginalName();
            $mimeType     = $file->getMimeType() ?? 'application/octet-stream';
            $fileSize     = $file->getSize();
            $extension    = $file->guessExtension() ?? pathinfo($originalName, PATHINFO_EXTENSION);
            $storedName   = uniqid('att_', true) . ($extension ? '.' . $extension : '');

            $file->move($attachmentsDir, $storedName);

            $attachmentsMeta[] = [
                'original_name' => $originalName,
                'stored_name'   => $storedName,
                'mime'          => $mimeType,
                'size'          => $fileSize,
            ];
        }

        return $attachmentsMeta;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  INDEX
    // ─────────────────────────────────────────────────────────────────────────
    #[Route('/', name: 'app_vault_index')]
    public function index(Request $request): Response
    {
        /** @var \App\Entity\User $user */
        $user         = $this->getUser();
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
            $qb->andWhere('s.deletedAt IS NOT NULL');
        } else {
            $qb->andWhere('s.deletedAt IS NULL');

            if ($archived) {
                $qb->andWhere('s.isArchived = true');
            } else {
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

        $activeCollection = null;
        if ($collectionId) {
            $activeCollection = $this->collectionRepository->find($collectionId);
            if ($activeCollection && $activeCollection->getUser() !== $user) {
                $activeCollection = null;
            }
        }

        return $this->render('vault/index.html.twig', [
            'secrets'          => $secrets,
            'collections'      => $collections,
            'activeCollection' => $activeCollection,
        ]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  NEW
    // ─────────────────────────────────────────────────────────────────────────
    #[Route('/new', name: 'app_vault_new', methods: ['GET', 'POST'])]
    public function new(Request $request): Response
    {
        /** @var \App\Entity\User $user */
        $user        = $this->getUser();
        $validTypes  = ['password', 'api_key', 'identity', 'note'];
        $defaultType = $request->query->get('type', 'password');
        if (! in_array($defaultType, $validTypes, true)) {
            $defaultType = 'password';
        }

        if ($request->isMethod('POST')) {
            if (! $this->isCsrfTokenValid('new_secret', $request->request->get('_token'))) {
                $this->addFlash('error', 'Action refusée : jeton de sécurité invalide.');

                return $this->renderNew($defaultType, $user, $request);
            }

            $masterPassword = $this->getMasterPasswordFromSession($request);
            if (null === $masterPassword) {
                $this->addFlash('error', 'Votre coffre est verrouillé. Veuillez vous reconnecter.');

                return $this->redirectToRoute('app_login');
            }

            $name = trim((string) $request->request->get('name', ''));
            $type = (string) $request->request->get('type', $defaultType);

            if ('' === $name || ! in_array($type, $validTypes, true)) {
                $this->addFlash('error', 'Veuillez renseigner un nom et un type de secret valide.');

                return $this->renderNew($defaultType, $user, $request);
            }

            $collection   = null;
            $collectionId = $request->request->get('collection_id');
            if ($collectionId) {
                $collection = $this->collectionRepository->find($collectionId);
            }
            if (! $collection || $collection->getUser() !== $user) {
                $this->addFlash('error', 'Veuillez sélectionner une collection valide.');

                return $this->renderNew($type, $user, $request);
            }

            $rawData = json_decode(
                (string) $request->request->get('data', '{}'),
                true
            ) ?? [];

            unset($rawData['attachments']);

            $attachmentsMeta = $this->handleFileUploads($request);
            if (! empty($attachmentsMeta)) {
                $rawData['attachments']       = $attachmentsMeta;
                $rawData['attachments_count'] = count($attachmentsMeta);
            } else {
                $rawData['attachments_count'] = 0;
            }

            $dataJson  = json_encode($rawData, JSON_UNESCAPED_UNICODE);
            $key       = $this->encryptionService->deriveKey($masterPassword, $user->getEncryptionKeySalt());
            $encrypted = $this->encryptionService->encrypt($dataJson, $key);

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

            try {
                $this->entityManager->flush();
            } catch (\Doctrine\DBAL\Exception\ConnectionLost $e) {
                $this->entityManager->getConnection()->close();
                $this->entityManager->clear();
                $this->entityManager->persist($secret);
                $this->logAction('CREATE', $secret, $request);
                $this->entityManager->flush();
            }

            $this->addFlash('success', 'Secret ajouté avec succès !');

            return $this->redirectToRoute('app_vault_index');
        }

        return $this->renderNew($defaultType, $user, $request);
    }

    private function renderNew(string $defaultType, $user, Request $request): Response
    {
        $currentCollection = null;
        $collectionId = $request->query->get('collection');
        if ($collectionId) {
            $currentCollection = $this->collectionRepository->find($collectionId);
        }

        return $this->render('vault/new.html.twig', [
            'defaultType'       => $defaultType,
            'collections'       => $this->collectionRepository->findByUser($user),
            'currentCollection' => $currentCollection,
        ]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  SHOW
    // ─────────────────────────────────────────────────────────────────────────
    #[Route('/{id}/show', name: 'app_vault_show', methods: ['GET', 'POST'])]
    public function show(Secret $secret, Request $request): Response
    {
        if ($secret->getUser() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        /** @var \App\Entity\User $user */
        $user             = $this->getUser();
        $decryptedData    = null;
        $decryptedPayload = null;
        $vaultLocked      = false;

        $masterPassword = $this->getMasterPasswordFromSession($request);

        if (null === $masterPassword) {
            $vaultLocked = true;
        } else {
            try {
                $key = $this->encryptionService->deriveKey($masterPassword, $user->getEncryptionKeySalt());
                $decryptedData    = $this->encryptionService->decrypt(
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
            } catch (\RuntimeException) {
                $vaultLocked = true;
            }
        }

        $template = $request->query->get('modal') ? 'vault/_show_partial.html.twig' : 'vault/show.html.twig';

        return $this->render($template, [
            'secret'           => $secret,
            'decryptedData'    => $decryptedData,
            'decryptedPayload' => $decryptedPayload,
            'vaultLocked'      => $vaultLocked,
        ]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  ATTACHMENT — serve a file stored on disk, after verifying ownership
    //  GET /vault/{id}/attachment/{filename}
    // ─────────────────────────────────────────────────────────────────────────
    #[Route('/{id}/attachment/{filename}', name: 'app_vault_attachment', methods: ['GET'])]
    public function serveAttachment(
        Secret $secret,
        string $filename,
        Request $request
    ): Response {
        // Security: only the owner can download
        if ($secret->getUser() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        $masterPassword = $this->getMasterPasswordFromSession($request);
        if (null === $masterPassword) {
            throw $this->createAccessDeniedException('Coffre verrouillé.');
        }

        /** @var \App\Entity\User $user */
        $user = $this->getUser();
        try {
            $key           = $this->encryptionService->deriveKey($masterPassword, $user->getEncryptionKeySalt());
            $decryptedData = $this->encryptionService->decrypt(
                $secret->getEncryptedData(),
                $secret->getIv(),
                $key
            );
        } catch (\RuntimeException) {
            throw $this->createAccessDeniedException('Impossible de déchiffrer le secret.');
        }

        $payload     = json_decode($decryptedData, true) ?? [];
        $attachments = $payload['attachments'] ?? [];

        // Find the requested file in the metadata list
        $meta = null;
        foreach ($attachments as $att) {
            if (($att['stored_name'] ?? '') === $filename) {
                $meta = $att;
                break;
            }
        }

        if (null === $meta) {
            throw $this->createNotFoundException('Pièce jointe introuvable.');
        }

        // Prevent path traversal
        $safeFilename = basename($filename);
        /** @var string $attachmentsDir */
        $attachmentsDir = (string) $this->getParameter('attachments_directory');
        $filePath = $attachmentsDir . DIRECTORY_SEPARATOR . $safeFilename;

        if (! file_exists($filePath) || ! is_file($filePath)) {
            throw $this->createNotFoundException('Fichier introuvable sur le serveur.');
        }

        $response = new BinaryFileResponse($filePath);

        $originalName = $meta['original_name'] ?? $safeFilename;
        $response->setContentDisposition(
            ResponseHeaderBag::DISPOSITION_INLINE,
            $originalName
        );

        $mimeType = $meta['mime'] ?? 'application/octet-stream';
        $response->headers->set('Content-Type', $mimeType);
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('Content-Security-Policy', "default-src 'none'");

        return $response;
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  EDIT
    // ─────────────────────────────────────────────────────────────────────────
    #[Route('/{id}/edit', name: 'app_vault_edit', methods: ['GET', 'POST'])]
    public function edit(Secret $secret, Request $request): Response
    {
        if ($secret->getUser() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        /** @var \App\Entity\User $user */
        $user          = $this->getUser();
        $decryptedData = null;
        $step          = 'edit';

        $masterPassword = $this->getMasterPasswordFromSession($request);
        if (null === $masterPassword) {
            $this->addFlash('error', 'Votre coffre est verrouillé. Veuillez vous reconnecter.');

            return $this->redirectToRoute('app_login');
        }

        try {
            $key           = $this->encryptionService->deriveKey($masterPassword, $user->getEncryptionKeySalt());
            $decryptedData = $this->encryptionService->decrypt(
                $secret->getEncryptedData(),
                $secret->getIv(),
                $key
            );
        } catch (\RuntimeException) {
            $this->addFlash('error', 'Impossible de déchiffrer ce secret.');

            return $this->redirectToRoute('app_vault_index');
        }

        if ($request->isMethod('POST')) {
            if (! $this->isCsrfTokenValid('edit' . $secret->getId(), $request->request->get('_token'))) {
                $this->addFlash('error', 'Action refusée : jeton de sécurité invalide.');
                $template = $request->query->get('modal') ? 'vault/_edit_partial.html.twig' : 'vault/edit.html.twig';

                return $this->render($template, [
                    'secret'        => $secret,
                    'decryptedData' => $decryptedData,
                    'step'          => $step,
                    'collections'   => $this->collectionRepository->findByUser($user),
                ]);
            }

            try {
                $name = $request->request->get('name');

                // Parse existing payload to keep existing attachments
                $existingPayload = json_decode($decryptedData, true) ?? [];
                $existingAttachments = $existingPayload['attachments'] ?? [];

                // Handle "keep existing" attachments (sent as JSON hidden field)
                $keepAttachmentsJson = $request->request->get('keep_attachments', '[]');
                $keepStoredNames = json_decode($keepAttachmentsJson, true) ?? [];

                // Filter existing attachments to only those the user wants to keep
                $keptAttachments = array_values(array_filter(
                    $existingAttachments,
                    fn ($att) => in_array($att['stored_name'] ?? '', $keepStoredNames, true)
                ));

                // Delete removed files from disk
                /** @var string $attachmentsDir */
                $attachmentsDir = (string) $this->getParameter('attachments_directory');
                foreach ($existingAttachments as $att) {
                    $storedName = $att['stored_name'] ?? '';
                    if ($storedName && ! in_array($storedName, $keepStoredNames, true)) {
                        $filePath = $attachmentsDir . DIRECTORY_SEPARATOR . basename($storedName);
                        if (file_exists($filePath)) {
                            @unlink($filePath);
                        }
                    }
                }

                // Handle new file uploads
                $newAttachments = $this->handleFileUploads($request);

                // Merge kept + new
                $allAttachments = array_merge($keptAttachments, $newAttachments);

                if ('password' === $secret->getType()) {
                    $payload = [
                        'type'     => 'password',
                        'username' => $request->request->get('username', ''),
                        'password' => $request->request->get('password', ''),
                        'website'  => $request->request->get('website', ''),
                        'notes'    => $request->request->get('notes', ''),
                    ];
                } elseif ('api_key' === $secret->getType()) {
                    $payload = [
                        'type'     => 'api_key',
                        'service'  => $request->request->get('api_service', ''),
                        'key'      => $request->request->get('api_key_value', ''),
                        'base_url' => $request->request->get('api_base_url', ''),
                        'env'      => $request->request->get('api_env', ''),
                        'notes'    => $request->request->get('notes', ''),
                    ];
                } elseif ('identity' === $secret->getType()) {
                    $payload = [
                        'type'      => 'identity',
                        'firstname' => $request->request->get('id_firstname', ''),
                        'lastname'  => $request->request->get('id_lastname', ''),
                        'email'     => $request->request->get('id_email', ''),
                        'phone'     => $request->request->get('id_phone', ''),
                        'company'   => $request->request->get('id_company', ''),
                        'city'      => $request->request->get('id_city', ''),
                        'country'   => $request->request->get('id_country', ''),
                        'address'   => $request->request->get('id_address', ''),
                        'notes'     => $request->request->get('notes', ''),
                    ];
                } else {
                    // note or fallback — keep raw text, add notes
                    $payload = [
                        'type'    => $secret->getType(),
                        'content' => $request->request->get('data', ''),
                        'notes'   => $request->request->get('notes', ''),
                    ];
                }

                // Attach files metadata
                if (! empty($allAttachments)) {
                    $payload['attachments']       = $allAttachments;
                    $payload['attachments_count'] = count($allAttachments);
                } else {
                    $payload['attachments_count'] = 0;
                }

                $dataToEncrypt = json_encode($payload, JSON_UNESCAPED_UNICODE);
                $encrypted = $this->encryptionService->encrypt($dataToEncrypt, $key);

                $secret->setName($name);
                $secret->setEncryptedData($encrypted['encrypted']);
                $secret->setIv($encrypted['iv']);

                $collectionId = $request->request->get('collection_id');
                $collection   = $collectionId ? $this->collectionRepository->find($collectionId) : null;
                if ($collection && $collection->getUser() === $user) {
                    $secret->setCollection($collection);
                } else {
                    $secret->setCollection(null);
                }

                $this->logAction('UPDATE', $secret, $request);
                $this->entityManager->flush();

                $this->addFlash('success', 'Secret modifié avec succès !');

                return $this->redirectToRoute('app_vault_index');
            } catch (\RuntimeException) {
                $this->addFlash('error', 'Erreur lors du chiffrement. Veuillez réessayer.');
            }
        }

        $template = $request->query->get('modal') ? 'vault/_edit_partial.html.twig' : 'vault/edit.html.twig';

        return $this->render($template, [
            'secret'        => $secret,
            'decryptedData' => $decryptedData,
            'step'          => $step,
            'collections'   => $this->collectionRepository->findByUser($user),
        ]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    //  DELETE / TRASH / RESTORE / FAVORITE / ARCHIVE
    // ─────────────────────────────────────────────────────────────────────────
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

        $logs = $this->entityManager->getRepository(AccessLog::class)->findBy(['secret' => $secret]);
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

    // ─────────────────────────────────────────────────────────────────────────
    //  Private helper — audit log
    // ─────────────────────────────────────────────────────────────────────────
    private function logAction(string $action, Secret $secret, Request $request): void
    {
        /** @var \App\Entity\User $user */
        $user = $this->getUser();
        $log  = new AccessLog();
        $log->setUser($user);
        $log->setSecret($secret);
        $log->setAction($action);
        $log->setIpAddress($request->getClientIp() ?? '0.0.0.0');
        $log->setUserAgent($request->headers->get('User-Agent') ?? '');
        $log->setCreatedAt(new \DateTimeImmutable());
        $this->entityManager->persist($log);
    }
}
