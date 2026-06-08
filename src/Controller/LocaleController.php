<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class LocaleController extends AbstractController
{
    #[Route('/change-locale/{locale}', name: 'change_locale')]
    public function changeLocale(string $locale, Request $request): Response
    {
        // Save selected language in session
        $request->getSession()->set('_locale', $locale);

        // Redirect user back
        $referer = $request->headers->get('referer');

        return $this->redirect(
            $referer ?: $this->generateUrl('app_vault_index')
        );
    }
}
