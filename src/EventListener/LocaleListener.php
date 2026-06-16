<?php

declare(strict_types=1);

namespace App\EventListener;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class LocaleListener implements EventSubscriberInterface
{
    private const ALLOWED_LOCALES = ['fr', 'en', 'ar'];
    private const DEFAULT_LOCALE  = 'fr';

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::REQUEST => [['onKernelRequest', 20]],
        ];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if (! $event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();

        if (! $request->hasSession()) {
            return;
        }

        $session = $request->getSession();
        $locale  = $session->get('_locale', self::DEFAULT_LOCALE);

        if (! in_array($locale, self::ALLOWED_LOCALES, true)) {
            $locale = self::DEFAULT_LOCALE;
            $session->set('_locale', $locale);
        }

        $request->setLocale($locale);
    }
}
