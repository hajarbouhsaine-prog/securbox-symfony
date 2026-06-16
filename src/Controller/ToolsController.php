<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\Secret;
use App\Repository\CollectionRepository;
use App\Service\EncryptionService;
use App\Trait\LogsActionTrait;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[IsGranted('ROLE_USER')]
#[Route('/tools')]
class ToolsController extends AbstractController
{
    use LogsActionTrait;

    public function __construct(
        private EntityManagerInterface $entityManager,
        private CollectionRepository $collectionRepository,
        private EncryptionService $encryptionService
    ) {
    }

    // ────────────────────────────────────────────────────────────────
    //  Générateur de mots de passe
    // ────────────────────────────────────────────────────────────────
    #[Route('/generator', name: 'tools_generator')]
    public function generator(): Response
    {
        return $this->render('tools/generator.html.twig');
    }

    // ────────────────────────────────────────────────────────────────
    //  Export
    // ────────────────────────────────────────────────────────────────
    #[Route('/export', name: 'tools_export', methods: ['GET', 'POST'])]
    public function export(Request $request): Response
    {
        /** @var \App\Entity\User $user */
        $user        = $this->getUser();
        $collections = $this->collectionRepository->findByUser($user);

        if ($request->isMethod('POST')) {
            // ── Validation CSRF ──
            if (! $this->isCsrfTokenValid('tools_export', $request->request->get('_token'))) {
                $this->addFlash('error', 'Action refusée : jeton de sécurité invalide.');

                return $this->redirectToRoute('tools_export');
            }

            $masterPassword = trim($request->request->get('master_password', ''));
            $collectionId   = $request->request->get('collection_id', '');
            $format         = $request->request->get('format', 'json');

            if (! in_array($format, ['json', 'csv', 'json_encrypted'], true)) {
                $format = 'json';
            }

            if ('' === $masterPassword) {
                $this->addFlash('error', 'Le mot de passe maître est requis pour déchiffrer vos secrets.');

                return $this->redirectToRoute('tools_export');
            }

            // ── Récupération des secrets ──
            $qb = $this->entityManager->getRepository(Secret::class)
                ->createQueryBuilder('s')
                ->where('s.user = :user')
                ->andWhere('s.deletedAt IS NULL')
                ->setParameter('user', $user);

            if ('' !== $collectionId) {
                $qb->andWhere('s.collection = :col')->setParameter('col', (int) $collectionId);
            }

            $secrets = $qb->getQuery()->getResult();

            if (0 === count($secrets)) {
                $this->addFlash('error', 'Cette collection ne contient aucun secret à exporter.');

                return $this->redirectToRoute('tools_export');
            }

            $now = new \DateTimeImmutable();

            // ── Export JSON chiffré : pas de déchiffrement, on dump les données brutes ──
            if ('json_encrypted' === $format) {
                $items = [];
                foreach ($secrets as $secret) {
                    $items[] = [
                        'id'             => $secret->getId(),
                        'name'           => $secret->getName(),
                        'type'           => $secret->getType(),
                        'encryptedData'  => $secret->getEncryptedData(),
                        'iv'             => $secret->getIv(),
                        'isFavorite'     => $secret->isFavorite(),
                        'isArchived'     => $secret->isArchived(),
                        'collection'     => $secret->getCollection()?->getName(),
                        'createdAt'      => $secret->getCreatedAt()?->format('c'),
                        'updatedAt'      => $secret->getUpdatedAt()?->format('c'),
                    ];
                }

                $export = [
                    'format'              => 'securbox',
                    'version'             => '1.0',
                    'encrypted'           => true,
                    'encryptionKeySalt'   => $user->getEncryptionKeySalt(),
                    'exportedAt'          => $now->format('c'),
                    'totalCount'          => count($items),
                    'items'               => $items,
                ];

                $json     = json_encode($export, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
                $filename = sprintf('securbox_export_encrypted_%s.json', $now->format('Ymd_His'));

                // AJOUTÉ : Log juste avant le return de l'export JSON chiffré
                $this->logAction($user, 'EXPORT', $request, 'Export JSON chiffré — ' . count($secrets) . ' secrets');

                return new Response($json, 200, [
                    'Content-Type'        => 'application/json; charset=UTF-8',
                    'Content-Disposition' => 'attachment; filename="' . $filename . '"',
                ]);
            }

            // ── Dérivation de la clé de chiffrement ──
            $key = $this->encryptionService->deriveKey(
                $masterPassword,
                $user->getEncryptionKeySalt()
            );

            $items = [];
            $errors = 0;
            $failedNames = [];

            foreach ($secrets as $secret) {
                try {
                    $raw     = $this->encryptionService->decrypt(
                        $secret->getEncryptedData(),
                        $secret->getIv(),
                        $key
                    );
                    $payload = json_decode($raw, true) ?? ['data' => $raw];
                } catch (\RuntimeException) {
                    // Mot de passe maître incorrect / clé différente pour ce secret → on l'ignore
                    ++$errors;
                    $failedNames[] = $secret->getName();
                    continue;
                }

                // ── Format natif SecurBox : un seul format, types de l'app uniquement ──
                $items[] = [
                    'id'          => $secret->getId(),
                    'name'        => $secret->getName(),
                    'type'        => $secret->getType(),
                    'data'        => $payload,
                    'isFavorite'  => $secret->isFavorite(),
                    'isArchived'  => $secret->isArchived(),
                    'collection'  => $secret->getCollection()?->getName(),
                    'createdAt'   => $secret->getCreatedAt()?->format('c'),
                    'updatedAt'   => $secret->getUpdatedAt()?->format('c'),
                ];
            }

            if ($errors > 0 && 0 === count($items)) {
                $this->addFlash('error', 'Mot de passe maître incorrect. Aucun secret n\'a pu être déchiffré.');

                return $this->redirectToRoute('tools_export');
            }

            if ($errors > 0) {
                $this->addFlash('error', sprintf(
                    '%d secret(s) n\'ont pas pu être déchiffrés et n\'apparaissent pas dans l\'export : %s. '
                    . 'Cela arrive quand un secret a été chiffré avec un mot de passe maître différent de celui saisi ici.',
                    $errors,
                    implode(', ', $failedNames)
                ));
            }

            // ── Export CSV ──
            if ('csv' === $format) {
                $columns = ['id', 'name', 'type', 'username', 'password', 'website', 'notes', 'firstname', 'lastname', 'email', 'phone', 'address', 'city', 'country', 'service', 'api_key', 'environment', 'isFavorite', 'isArchived', 'collection', 'createdAt'];

                $fh = fopen('php://temp', 'r+');
                fputcsv($fh, $columns);

                foreach ($items as $item) {
                    $data = is_array($item['data']) ? $item['data'] : [];
                    $row  = [];
                    foreach ($columns as $col) {
                        $row[$col] = match ($col) {
                            'id'         => $item['id'],
                            'name'       => $item['name'],
                            'type'       => $item['type'],
                            'isFavorite' => $item['isFavorite'] ? '1' : '0',
                            'isArchived' => $item['isArchived'] ? '1' : '0',
                            'collection' => $item['collection'],
                            'createdAt'  => $item['createdAt'],
                            'notes'      => $data['notes'] ?? $data['content'] ?? '',
                            'api_key'    => $data['key'] ?? $data['api_key'] ?? '',
                            default      => $data[$col] ?? '',
                        };
                    }
                    fputcsv($fh, $row);
                }

                rewind($fh);
                $csv = stream_get_contents($fh);
                fclose($fh);

                $filename = sprintf('securbox_export_%s.csv', $now->format('Ymd_His'));

                // AJOUTÉ : Log juste avant le return de l'export CSV
                $this->logAction($user, 'EXPORT', $request, 'Export CSV — ' . count($items) . ' secrets');

                return new Response($csv, 200, [
                    'Content-Type'        => 'text/csv; charset=UTF-8',
                    'Content-Disposition' => 'attachment; filename="' . $filename . '"',
                ]);
            }

            // ── Export JSON (déchiffré) ──
            $export = [
                'format'     => 'securbox',
                'version'    => '1.0',
                'exportedAt' => (new \DateTimeImmutable())->format('c'),
                'totalCount' => count($items),
                'items'      => $items,
            ];

            $json     = json_encode($export, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
            $filename = sprintf(
                'securbox_export_%s.json',
                $now->format('Ymd_His')
            );

            // AJOUTÉ : Log juste avant le return de l'export JSON déchiffré
            $this->logAction($user, 'EXPORT', $request, 'Export JSON — ' . count($items) . ' secrets');

            return new Response($json, 200, [
                'Content-Type'        => 'application/json; charset=UTF-8',
                'Content-Disposition' => 'attachment; filename="' . $filename . '"',
            ]);
        }

        return $this->render('tools/export.html.twig', [
            'collections' => $collections,
        ]);
    }

    // ────────────────────────────────────────────────────────────────
    //  Import
    // ────────────────────────────────────────────────────────────────
    #[Route('/import', name: 'tools_import', methods: ['GET', 'POST'])]
    public function import(Request $request): Response
    {
        /** @var \App\Entity\User $user */
        $user        = $this->getUser();
        $collections = $this->collectionRepository->findByUser($user);

        if (! $request->isMethod('POST')) {
            return $this->render('tools/import.html.twig', [
                'collections' => $collections,
            ]);
        }

        // ── Validation CSRF ──
        if (! $this->isCsrfTokenValid('tools_import', $request->request->get('_token'))) {
            $this->addFlash('error', 'Action refusée : jeton de sécurité invalide.');

            return $this->redirectToRoute('tools_import');
        }

        $masterPassword = trim($request->request->get('master_password', ''));
        $collectionId   = $request->request->get('collection_id', '');
        $uploadedFile   = $request->files->get('import_file');

        // ── Validations basiques ──
        if ('' === $masterPassword) {
            $this->addFlash('error', 'Le mot de passe maître est requis pour chiffrer les secrets importés.');

            return $this->redirectToRoute('tools_import');
        }

        if (! $uploadedFile || ! $uploadedFile->isValid()) {
            $this->addFlash('error', 'Veuillez sélectionner un fichier JSON ou CSV valide.');

            return $this->redirectToRoute('tools_import');
        }

        $extension = strtolower($uploadedFile->getClientOriginalExtension());
        if (! in_array($extension, ['json', 'csv'], true)) {
            $this->addFlash('error', 'Seuls les fichiers .json et .csv sont acceptés.');

            return $this->redirectToRoute('tools_import');
        }

        if ($uploadedFile->getSize() > 5 * 1024 * 1024) {
            $this->addFlash('error', 'Le fichier ne doit pas dépasser 5 Mo.');

            return $this->redirectToRoute('tools_import');
        }

        // ── Lecture du fichier ──
        $raw = file_get_contents($uploadedFile->getPathname());
        if (false === $raw) {
            $this->addFlash('error', 'Impossible de lire le fichier.');

            return $this->redirectToRoute('tools_import');
        }

        $format = null;
        $items  = [];

        if ('csv' === $extension) {
            $items = $this->parseCsvFile($raw);
            if (null === $items) {
                $this->addFlash('error', 'Le fichier CSV est invalide ou vide.');

                return $this->redirectToRoute('tools_import');
            }
            $format = 'securbox';
        } else {
            $json = json_decode($raw, true);
            if (null === $json) {
                $this->addFlash('error', 'Le fichier JSON est invalide ou corrompu.');

                return $this->redirectToRoute('tools_import');
            }

            // ── Détection du format ──
            if (isset($json['format']) && 'securbox' === $json['format']) {
                $format = (isset($json['encrypted']) && true === $json['encrypted'])
                    ? 'securbox_encrypted'
                    : 'securbox';
            }

            if (null === $format) {
                $this->addFlash('error', 'Format non reconnu. Utilisez un export SecurBox (.json ou .csv).');

                return $this->redirectToRoute('tools_import');
            }

            if ('securbox_encrypted' === $format && $json['encryptionKeySalt'] !== $user->getEncryptionKeySalt()) {
                $this->addFlash('error', 'Ce fichier chiffré provient d\'un autre compte et ne peut pas être réimporté ici. Utilisez un export .json (déchiffré) à la place.');

                return $this->redirectToRoute('tools_import');
            }

            $items = $json['items'] ?? [];
        }

        // ── Résolution de la collection cible ──
        $targetCollection = null;
        if ('' !== $collectionId) {
            $targetCollection = $this->collectionRepository->find((int) $collectionId);
            if (! $targetCollection || $targetCollection->getUser() !== $user) {
                $this->addFlash('error', 'Collection invalide.');

                return $this->redirectToRoute('tools_import');
            }
        }

        // ── Dérivation de la clé ──
        $key = $this->encryptionService->deriveKey(
            $masterPassword,
            $user->getEncryptionKeySalt()
        );

        // ── Import des items ──
        $imported   = 0;
        $skipped    = 0;
        $firstError = null;

        foreach ($items as $item) {
            try {
                if ('securbox_encrypted' === $format) {
                    $name = trim($item['name'] ?? 'Sans titre');
                    if ('' === $name) {
                        $name = 'Importé';
                    }

                    $secret = new Secret();
                    $secret->setUser($user);
                    $secret->setName($name);
                    $secret->setType($item['type'] ?? 'note');
                    $secret->setEncryptedData($item['encryptedData'] ?? '');
                    $secret->setIv($item['iv'] ?? '');
                    $secret->setCreatedAt(new \DateTimeImmutable());
                    $secret->setIsFavorite((bool) ($item['isFavorite'] ?? false));
                    $secret->setIsArchived((bool) ($item['isArchived'] ?? false));

                    if (null !== $targetCollection) {
                        $secret->setCollection($targetCollection);
                    }

                    $this->entityManager->persist($secret);
                    ++$imported;
                    continue;
                }

                [$type, $payload] = $this->parseSecurboxItem($item);

                if (null === $type) {
                    ++$skipped;
                    continue;
                }

                $name = trim($item['name'] ?? 'Sans titre');
                if ('' === $name) {
                    $name = 'Importé';
                }

                $dataStr   = is_string($payload) ? $payload : json_encode($payload, JSON_UNESCAPED_UNICODE);
                $encrypted = $this->encryptionService->encrypt($dataStr, $key);

                $secret = new Secret();
                $secret->setUser($user);
                $secret->setName($name);
                $secret->setType($type);
                $secret->setEncryptedData($encrypted['encrypted']);
                $secret->setIv($encrypted['iv']);
                $secret->setCreatedAt(new \DateTimeImmutable());
                $secret->setIsFavorite((bool) ($item['isFavorite'] ?? false));
                $secret->setIsArchived((bool) ($item['isArchived'] ?? false));

                // La collection passée dans le formulaire a priorité
                if (null !== $targetCollection) {
                    $secret->setCollection($targetCollection);
                }

                $this->entityManager->persist($secret);
                ++$imported;

            } catch (\Throwable $e) {
                ++$skipped;
                if (null === $firstError) {
                    $firstError = $e->getMessage();
                }
            }
        }

        $this->entityManager->flush();

        // AJOUTÉ : Log de l'action juste après le flush()
        if ($imported > 0) {
            $this->logAction($user, 'IMPORT', $request, $imported . ' secret(s) importé(s) depuis .' . $extension);
        }

        if ($imported > 0) {
            $msg = sprintf('%d secret(s) importé(s) avec succès !', $imported);
            if ($skipped > 0) {
                $msg .= sprintf(' (%d ignoré(s) car non supporté(s))', $skipped);
            }
            $this->addFlash('success', $msg);
        } else {
            $error = 'Aucun secret n\'a pu être importé. Vérifiez le fichier.';
            if (null !== $firstError) {
                $error .= ' Détail : ' . $firstError;
            } elseif ($skipped > 0) {
                $error .= ' Tous les éléments du fichier sont d\'un type non supporté par SecurBox.';
            }
            $this->addFlash('error', $error);
        }

        return $this->redirectToRoute('app_vault_index');
    }

    // ────────────────────────────────────────────────────────────────
    //  Helpers privés
    // ────────────────────────────────────────────────────────────────

    /**
     * Parse un item au format SecurBox natif.
     * Retourne [type, payload] ou [null, null] si ignoré.
     */
    private function parseSecurboxItem(array $item): array
    {
        $validTypes = ['password', 'api_key', 'identity', 'note'];
        $type = $item['type'] ?? null;

        if (! in_array($type, $validTypes, true)) {
            return [null, null];
        }

        $data = $item['data'] ?? '';

        return [$type, $data];
    }

    /**
     * Parse un export CSV SecurBox et le convertit en tableau d'items
     * au même format que les items JSON ('type', 'data', 'name', etc.).
     *
     * Retourne null si le fichier est vide ou invalide.
     *
     * @return array<int, array<string, mixed>>|null
     */
    private function parseCsvFile(string $raw): ?array
    {
        $fh = fopen('php://temp', 'r+');
        fwrite($fh, $raw);
        rewind($fh);

        $header = fgetcsv($fh);
        if (false === $header || null === $header) {
            fclose($fh);

            return null;
        }

        // Normalise les en-têtes (suppression BOM éventuel, espaces)
        $header = array_map(static fn ($h) => trim((string) $h, " \t\n\r\0\x0B\xEF\xBB\xBF"), $header);

        $validTypes = ['password', 'api_key', 'identity', 'note'];
        $items = [];

        while (($row = fgetcsv($fh)) !== false) {
            if ($row === [null]) {
                continue;
            }

            $assoc = [];
            foreach ($header as $i => $col) {
                $assoc[$col] = $row[$i] ?? '';
            }

            $type = $assoc['type'] ?? null;
            if (! in_array($type, $validTypes, true)) {
                continue;
            }

            $data = match ($type) {
                'password' => [
                    'username' => $assoc['username'] ?? '',
                    'password' => $assoc['password'] ?? '',
                    'website'  => $assoc['website'] ?? '',
                    'notes'    => $assoc['notes'] ?? '',
                ],
                'api_key' => [
                    'service'     => $assoc['service'] ?? '',
                    'api_key'     => $assoc['api_key'] ?? '',
                    'environment' => $assoc['environment'] ?? '',
                    'notes'       => $assoc['notes'] ?? '',
                ],
                'identity' => [
                    'firstname' => $assoc['firstname'] ?? '',
                    'lastname'  => $assoc['lastname'] ?? '',
                    'email'     => $assoc['email'] ?? '',
                    'phone'     => $assoc['phone'] ?? '',
                    'address'   => $assoc['address'] ?? '',
                    'city'      => $assoc['city'] ?? '',
                    'country'   => $assoc['country'] ?? '',
                ],
                'note' => [
                    'content' => $assoc['notes'] ?? '',
                ],
                default => [],
            };

            $items[] = [
                'name'       => $assoc['name'] ?? 'Sans titre',
                'type'       => $type,
                'data'       => $data,
                'isFavorite' => ($assoc['isFavorite'] ?? '0') === '1',
                'isArchived' => ($assoc['isArchived'] ?? '0') === '1',
            ];
        }

        fclose($fh);

        return $items;
    }
}
