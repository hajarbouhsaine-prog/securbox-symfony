<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\Secret;
use App\Repository\CollectionRepository;
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
    public function __construct(private EntityManagerInterface $entityManager, private CollectionRepository $collectionRepository)
    {
    }

    #[Route('/generator', name: 'tools_generator')]
    public function generator(Request $request): Response
    {
        return $this->render('tools/generator.html.twig');
    }

    #[Route('/import', name: 'tools_import', methods: ['GET', 'POST'])]
    public function import(Request $request): Response
    {
        $user = $this->getUser();
        $collections = $this->collectionRepository->findByUser($user);

        if ($request->isMethod('POST')) {
            $this->addFlash('success', 'Fichier importé (simulation).');

            return $this->redirectToRoute('tools_import');
        }

        return $this->render('tools/import.html.twig', [
            'collections' => $collections,
        ]);
    }

    #[Route('/export', name: 'tools_export', methods: ['GET', 'POST'])]
    public function export(Request $request): Response
    {
        $user = $this->getUser();
        $collections = $this->collectionRepository->findByUser($user);

        if ($request->isMethod('POST')) {
            // simple JSON export of user's secrets
            $secrets = $this->entityManager->getRepository(Secret::class)->findBy(['user' => $user]);
            $data = [];
            foreach ($secrets as $s) {
                $data[] = [
                    'id' => $s->getId(),
                    'name' => $s->getName(),
                    'type' => $s->getType(),
                    'createdAt' => $s->getCreatedAt()?->format('c'),
                ];
            }
            $json = json_encode($data, JSON_PRETTY_PRINT);
            $filename = 'vault_export_' . date('Ymd_His') . '.json';

            return new Response($json, 200, [
                'Content-Type' => 'application/json',
                'Content-Disposition' => 'attachment; filename="' . $filename . '"',
            ]);
        }

        return $this->render('tools/export.html.twig', [
            'collections' => $collections,
        ]);
    }
}
