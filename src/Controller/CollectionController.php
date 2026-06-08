<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\Collection;
use App\Repository\CollectionRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[IsGranted('ROLE_USER')]
#[Route('/collections')]
class CollectionController extends AbstractController
{
    public function __construct(private EntityManagerInterface $entityManager)
    {
    }

    #[Route('/', name: 'app_collection_index')]
    public function index(CollectionRepository $repo): Response
    {
        $collections = $repo->findByUser($this->getUser());

        return $this->render('collection/index.html.twig', [
            'collections' => $collections,
        ]);
    }

    #[Route('/new', name: 'app_collection_new', methods: ['GET', 'POST'])]
    public function new(Request $request): Response
    {
        if ($request->isMethod('POST')) {
            $name        = trim($request->request->get('name', ''));
            $description = trim($request->request->get('description', ''));

            if (empty($name)) {
                $this->addFlash('error', 'Le nom de la collection est requis.');

                return $this->redirectToRoute('app_collection_new');
            }

            $collection = new Collection();
            $collection->setName($name);
            $collection->setDescription($description ?: null);
            /** @var \App\Entity\User $user */
            $user = $this->getUser();
            $collection->setUser($user);

            $this->entityManager->persist($collection);
            $this->entityManager->flush();

            $this->addFlash('success', 'Collection "' . $name . '" créée avec succès !');

            return $this->redirectToRoute('app_vault_index', ['collection' => $collection->getId()]);
        }

        return $this->render('collection/new.html.twig');
    }

    #[Route('/{id}/delete', name: 'app_collection_delete', methods: ['POST'])]
    public function delete(Collection $collection, Request $request): Response
    {
        if ($collection->getUser() !== $this->getUser()) {
            throw $this->createAccessDeniedException();
        }

        if ($this->isCsrfTokenValid('delete_collection' . $collection->getId(), $request->request->get('_token'))) {
            // Detach secrets from this collection before deleting
            foreach ($collection->getSecrets() as $secret) {
                $secret->setCollection(null);
            }
            $this->entityManager->remove($collection);
            $this->entityManager->flush();
            $this->addFlash('success', 'Collection supprimée.');
        }

        return $this->redirectToRoute('app_collection_index');
    }
}
