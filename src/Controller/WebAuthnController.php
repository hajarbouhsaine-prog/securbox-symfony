<?php

declare(strict_types=1);

namespace App\Controller;

use App\Entity\User;
use App\Entity\WebAuthnCredential;
use App\Trait\LogsActionTrait;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * FIDO2 / WebAuthn — Enregistrement et authentification.
 *
 * Implémentation sans dépendance CBOR externe.
 * Le décodeur CBOR minimal est intégré directement dans ce controller.
 *
 * ⚠️  Accéder via https://localhost:8443 (après mkcert)
 *      ou http://localhost:8000 — PAS 127.0.0.1 (IP bloquée par WebAuthn)
 *
 * Routes (inchangées par rapport à l'ancienne version) :
 *   POST /webauthn/register/options   → webauthn_register_options
 *   POST /webauthn/register/verify    → webauthn_register_verify
 *   GET  /webauthn/auth/options       → webauthn_auth_options
 *   POST /webauthn/auth/verify        → webauthn_auth_verify
 *   POST /webauthn/credential/{id}/delete → webauthn_delete
 */
#[Route('/webauthn')]
class WebAuthnController extends AbstractController
{
    use LogsActionTrait;

    /**
     * Origine attendue — doit correspondre exactement à l'URL du navigateur.
     *
     * Après mkcert :  'https://localhost:8443'
     * Sans HTTPS  :   'http://localhost:8000'
     *
     * ⚠️  Ne jamais mettre 127.0.0.1 ici — WebAuthn bloque les adresses IP.
     */
    private const ORIGIN  = 'https://localhost:8443';
    private const RP_NAME = 'SecurBox';
    private const TIMEOUT = 60000;

    public function __construct(
        private EntityManagerInterface $entityManager
    ) {
    }

    // ════════════════════════════════════════════════════════════════
    //  ENREGISTREMENT — Étape 1 : options
    // ════════════════════════════════════════════════════════════════

    #[IsGranted('ROLE_USER')]
    #[Route('/register/options', name: 'webauthn_register_options', methods: ['POST', 'GET'])]
    public function registerOptions(Request $request): JsonResponse
    {
        /** @var User $user */
        $user      = $this->getUser();
        $challenge = random_bytes(32);

        $request->getSession()->set('webauthn_register_challenge', base64_encode($challenge));

        $existing = $this->entityManager->getRepository(WebAuthnCredential::class)->findBy(['user' => $user]);
        $excludeCredentials = array_map(fn ($c) => [
            'type' => 'public-key',
            'id'   => $c->getCredentialId(),
        ], $existing);

        return new JsonResponse([
            'rp' => ['name' => self::RP_NAME],
            // Pas de rp.id → navigateur dérive depuis l'URL (obligatoire pour localhost)
            'user' => [
                'id'          => $this->b64uEncode((string) $user->getId()),
                'name'        => $user->getEmail(),
                'displayName' => $user->getEmail(),
            ],
            'challenge'          => $this->b64uEncode($challenge),
            'pubKeyCredParams'   => [
                ['type' => 'public-key', 'alg' => -7],    // ES256 — ECDSA P-256 (TouchID, YubiKey)
                ['type' => 'public-key', 'alg' => -257],  // RS256 — RSA (Windows Hello)
            ],
            'timeout'            => self::TIMEOUT,
            'excludeCredentials' => $excludeCredentials,
            'authenticatorSelection' => [
                'userVerification' => 'preferred',
                'residentKey'      => 'discouraged',
            ],
            'attestation' => 'none',
        ]);
    }

    // ════════════════════════════════════════════════════════════════
    //  ENREGISTREMENT — Étape 2 : vérification + stockage
    // ════════════════════════════════════════════════════════════════

    #[IsGranted('ROLE_USER')]
    #[Route('/register/verify', name: 'webauthn_register_verify', methods: ['POST'])]
    public function registerVerify(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $this->getUser();
        $data = json_decode($request->getContent(), true);

        if (! $data) {
            return new JsonResponse(['error' => 'Corps de requête invalide.'], 400);
        }

        // ── Challenge ────────────────────────────────────────────────
        $storedChallenge = $request->getSession()->get('webauthn_register_challenge');
        if (! $storedChallenge) {
            return new JsonResponse(['error' => 'Challenge expiré. Rechargez la page.'], 400);
        }
        $request->getSession()->remove('webauthn_register_challenge');

        try {
            // Gérer les deux formats possibles envoyés par le JS
            // Format A (ancien twig) : response.clientDataJSON
            // Format B (nouveau twig) : clientDataJSON directement
            $response = $data['response'] ?? $data;

            $clientDataRaw  = $this->b64uDecode($response['clientDataJSON']    ?? '');
            $attestationRaw = $this->b64uDecode($response['attestationObject'] ?? '');
            $credentialId   = $data['id'] ?? '';
            $keyName        = mb_substr(trim($data['name'] ?? 'Clé de sécurité'), 0, 100) ?: 'Clé de sécurité';

            if (! $clientDataRaw || ! $attestationRaw || ! $credentialId) {
                return new JsonResponse(['error' => 'Réponse incomplète de l\'authenticator.'], 400);
            }

            // ── Vérifier clientDataJSON ──────────────────────────────
            $clientData = json_decode($clientDataRaw, true);
            if (! $clientData) {
                return new JsonResponse(['error' => 'clientDataJSON illisible.'], 400);
            }

            if (($clientData['type'] ?? '') !== 'webauthn.create') {
                return new JsonResponse(['error' => 'Type d\'opération incorrect.'], 400);
            }

            // Challenge : comparer en base64url
            $expectedChallenge = $this->b64uEncode(base64_decode($storedChallenge));
            if (! hash_equals($expectedChallenge, $clientData['challenge'] ?? '')) {
                return new JsonResponse(['error' => 'Challenge invalide.'], 400);
            }

            // Origine
            if (! $this->originOk($clientData['origin'] ?? '')) {
                return new JsonResponse([
                    'error' => 'Origine invalide : ' . ($clientData['origin'] ?? '—')
                        . '. Accédez via ' . self::ORIGIN,
                ], 400);
            }

            // ── Décoder l'attestationObject (CBOR) ───────────────────
            $attObj = $this->cborDecode($attestationRaw);
            if (! $attObj || ! isset($attObj['authData'])) {
                return new JsonResponse(['error' => 'attestationObject illisible.'], 400);
            }

            $authData = $attObj['authData'];
            if (strlen($authData) < 55) {
                return new JsonResponse(['error' => 'authData trop court.'], 400);
            }

            // ── Vérifier rpIdHash ─────────────────────────────────────
            $rpIdHash     = substr($authData, 0, 32);
            $expectedHost = parse_url(self::ORIGIN, PHP_URL_HOST) ?? 'localhost';
            if (! hash_equals(hash('sha256', $expectedHost, true), $rpIdHash)) {
                return new JsonResponse(['error' => 'rpIdHash invalide.'], 400);
            }

            // ── Vérifier flags (User Presence = bit 0) ───────────────
            $flags = ord($authData[32]);
            if (! ($flags & 0x01)) {
                return new JsonResponse(['error' => 'User Presence non confirmé.'], 400);
            }

            // ── Extraire credentialId et clé publique ─────────────────
            $credIdLen  = (ord($authData[53]) << 8) | ord($authData[54]);
            $credId     = substr($authData, 55, $credIdLen);
            $pubKeyCBOR = substr($authData, 55 + $credIdLen);

            if (! $credId || ! $pubKeyCBOR) {
                return new JsonResponse(['error' => 'credentialId ou clé publique manquants.'], 400);
            }

            // ── Unicité ───────────────────────────────────────────────
            $credIdB64 = $this->b64uEncode($credId);
            if ($this->entityManager->getRepository(WebAuthnCredential::class)->findOneBy(['credentialId' => $credIdB64])) {
                return new JsonResponse(['error' => 'Cette clé est déjà enregistrée.'], 409);
            }

            // ── Persister ─────────────────────────────────────────────
            $credential = new WebAuthnCredential($user, $credIdB64, base64_encode($pubKeyCBOR), $keyName);
            $this->entityManager->persist($credential);
            $this->entityManager->flush();

            $this->logAction($user, 'WEBAUTHN_REGISTERED', $request, 'Clé FIDO2 enregistrée : ' . $keyName);

            return new JsonResponse(['success' => true, 'message' => 'Clé « ' . $keyName . ' » enregistrée !']);

        } catch (\Throwable $e) {
            return new JsonResponse(['error' => 'Erreur serveur : ' . $e->getMessage()], 500);
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  AUTHENTIFICATION 2FA — Étape 1 : options
    // ════════════════════════════════════════════════════════════════

    #[Route('/auth/options', name: 'webauthn_auth_options', methods: ['GET', 'POST'])]
    public function authOptions(Request $request): JsonResponse
    {
        $userId = $request->getSession()->get('2fa_user_id');
        $user   = $userId
            ? $this->entityManager->getRepository(User::class)->find($userId)
            : $this->getUser();

        if (! $user instanceof User) {
            return new JsonResponse(['error' => 'Non authentifié.'], 401);
        }

        $credentials = $this->entityManager->getRepository(WebAuthnCredential::class)->findBy(['user' => $user]);
        if (empty($credentials)) {
            return new JsonResponse(['error' => 'Aucune clé FIDO2 enregistrée.'], 404);
        }

        $challenge = random_bytes(32);
        $request->getSession()->set('webauthn_auth_challenge', base64_encode($challenge));
        $request->getSession()->set('webauthn_auth_user_id', $user->getId());

        return new JsonResponse([
            'challenge'        => $this->b64uEncode($challenge),
            'timeout'          => self::TIMEOUT,
            'userVerification' => 'preferred',
            'allowCredentials' => array_map(fn ($c) => [
                'type'       => 'public-key',
                'id'         => $c->getCredentialId(),
                'transports' => ['usb', 'nfc', 'ble', 'internal'],
            ], $credentials),
        ]);
    }

    // ════════════════════════════════════════════════════════════════
    //  AUTHENTIFICATION 2FA — Étape 2 : vérification signature
    // ════════════════════════════════════════════════════════════════

    #[Route('/auth/verify', name: 'webauthn_auth_verify', methods: ['POST'])]
    public function authVerify(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true);
        if (! $data) {
            return new JsonResponse(['error' => 'Données invalides.'], 400);
        }

        $storedChallenge = $request->getSession()->get('webauthn_auth_challenge');
        $authUserId      = $request->getSession()->get('webauthn_auth_user_id');

        if (! $storedChallenge || ! $authUserId) {
            return new JsonResponse(['error' => 'Session expirée.'], 400);
        }

        $request->getSession()->remove('webauthn_auth_challenge');
        $request->getSession()->remove('webauthn_auth_user_id');

        try {
            $response = $data['response'] ?? $data;

            $credentialId   = $data['id'] ?? '';
            $clientDataRaw  = $this->b64uDecode($response['clientDataJSON']    ?? '');
            $authDataRaw    = $this->b64uDecode($response['authenticatorData'] ?? '');
            $signatureRaw   = $this->b64uDecode($response['signature']         ?? '');

            if (! $clientDataRaw || ! $authDataRaw || ! $signatureRaw || ! $credentialId) {
                return new JsonResponse(['error' => 'Réponse incomplète.'], 400);
            }

            // ── clientDataJSON ────────────────────────────────────────
            $clientData = json_decode($clientDataRaw, true);
            if (($clientData['type'] ?? '') !== 'webauthn.get') {
                return new JsonResponse(['error' => 'Type incorrect.'], 400);
            }

            $expectedChallenge = $this->b64uEncode(base64_decode($storedChallenge));
            if (! hash_equals($expectedChallenge, $clientData['challenge'] ?? '')) {
                return new JsonResponse(['error' => 'Challenge invalide.'], 400);
            }

            if (! $this->originOk($clientData['origin'] ?? '')) {
                return new JsonResponse(['error' => 'Origine invalide.'], 400);
            }

            // ── rpIdHash ──────────────────────────────────────────────
            $rpIdHash     = substr($authDataRaw, 0, 32);
            $expectedHost = parse_url(self::ORIGIN, PHP_URL_HOST) ?? 'localhost';
            if (! hash_equals(hash('sha256', $expectedHost, true), $rpIdHash)) {
                return new JsonResponse(['error' => 'rpIdHash invalide.'], 400);
            }

            // ── Trouver la clé ────────────────────────────────────────
            $credential = $this->entityManager->getRepository(WebAuthnCredential::class)
                ->findOneBy(['credentialId' => $credentialId]);

            if (! $credential || $credential->getUser()->getId() !== $authUserId) {
                return new JsonResponse(['error' => 'Clé introuvable.'], 404);
            }

            // ── Vérifier la signature ─────────────────────────────────
            $clientDataHash = hash('sha256', $clientDataRaw, true);
            $signedData     = $authDataRaw . $clientDataHash;
            $pubKeyCBOR     = base64_decode($credential->getPublicKey());

            $coseKey = $this->cborDecode($pubKeyCBOR);
            if (! $coseKey || ! $this->verifyCoseSignature($signedData, $signatureRaw, $coseKey)) {
                return new JsonResponse(['error' => 'Signature invalide.'], 401);
            }

            // ── signCount (anti-clonage) ──────────────────────────────
            if (strlen($authDataRaw) >= 37) {
                $newCount = unpack('N', substr($authDataRaw, 33, 4))[1];
                if (0 !== $newCount && $newCount <= $credential->getSignCount()) {
                    $this->logAction(
                        $credential->getUser(),
                        'WEBAUTHN_CLONE_SUSPECTED',
                        $request,
                        'Compteur non incrémenté : ' . $credential->getName()
                    );
                }
                if ($newCount > 0) {
                    $credential->setSignCount($newCount);
                }
            }

            if (method_exists($credential, 'markUsed')) {
                $credential->markUsed();
            }
            $this->entityManager->flush();

            $request->getSession()->set('2fa_webauthn_verified', true);
            $request->getSession()->set('2fa_verified_at', time());

            $this->logAction(
                $credential->getUser(),
                'WEBAUTHN_AUTH_SUCCESS',
                $request,
                'Auth FIDO2 réussie : ' . $credential->getName()
            );

            return new JsonResponse(['success' => true, 'redirect' => '/vault']);

        } catch (\Throwable $e) {
            return new JsonResponse(['error' => 'Erreur serveur : ' . $e->getMessage()], 500);
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  SUPPRESSION d'une clé
    // ════════════════════════════════════════════════════════════════

    #[IsGranted('ROLE_USER')]
    #[Route('/credential/{id}/delete', name: 'webauthn_delete', methods: ['POST'])]
    public function deleteCredential(int $id, Request $request): Response
    {
        /** @var User $user */
        $user       = $this->getUser();
        $credential = $this->entityManager->getRepository(WebAuthnCredential::class)->find($id);

        if (! $credential || $credential->getUser() !== $user) {
            $this->addFlash('error', 'Clé introuvable.');

            return $this->redirectToRoute('app_settings_security');
        }

        if (! $this->isCsrfTokenValid('webauthn_delete_' . $id, $request->request->get('_token'))) {
            $this->addFlash('error', 'Jeton de sécurité invalide.');

            return $this->redirectToRoute('app_settings_security');
        }

        $name = $credential->getName();
        $this->entityManager->remove($credential);
        $this->entityManager->flush();

        $this->logAction($user, 'WEBAUTHN_DELETED', $request, 'Clé supprimée : ' . $name);
        $this->addFlash('success', 'Clé "' . $name . '" supprimée.');

        return $this->redirectToRoute('app_settings_security');
    }

    // ════════════════════════════════════════════════════════════════
    //  DÉCODEUR CBOR MINIMAL
    //  Supporte : unsigned int, negative int, byte string,
    //             text string, array, map — tout ce que WebAuthn utilise.
    // ════════════════════════════════════════════════════════════════

    private function cborDecode(string $bytes): mixed
    {
        $pos = 0;

        return $this->cborRead($bytes, $pos);
    }

    private function cborRead(string $bytes, int &$pos): mixed
    {
        if ($pos >= strlen($bytes)) {
            return null;
        }

        $initial = ord($bytes[$pos++]);
        $major   = ($initial >> 5) & 7;
        $info    = $initial & 0x1F;

        // Lire la valeur/longueur selon l'info complémentaire
        $val = match (true) {
            $info <= 23 => $info,
            24 === $info => ord($bytes[$pos++]),
            25 === $info => (function () use ($bytes, &$pos): int {
                $v = (ord($bytes[$pos]) << 8) | ord($bytes[$pos + 1]);
                $pos += 2;

                return $v;
            })(),
            26 === $info => (function () use ($bytes, &$pos): int {
                $v = (ord($bytes[$pos]) << 24) | (ord($bytes[$pos + 1]) << 16)
                   | (ord($bytes[$pos + 2]) << 8) | ord($bytes[$pos + 3]);
                $pos += 4;

                return $v;
            })(),
            default => 0,
        };

        return match ($major) {
            0 => $val,       // Unsigned integer
            1 => -1 - $val,  // Negative integer
            2 => (function () use ($bytes, &$pos, $val): string {  // Byte string
                $s = substr($bytes, $pos, $val);
                $pos += $val;

                return $s;
            })(),
            3 => (function () use ($bytes, &$pos, $val): string {  // Text string
                $s = substr($bytes, $pos, $val);
                $pos += $val;

                return $s;
            })(),
            4 => (function () use ($bytes, &$pos, $val): array {   // Array
                $arr = [];
                for ($i = 0; $i < $val; ++$i) {
                    $arr[] = $this->cborRead($bytes, $pos);
                }

                return $arr;
            })(),
            5 => (function () use ($bytes, &$pos, $val): array {   // Map
                $map = [];
                for ($i = 0; $i < $val; ++$i) {
                    $k       = $this->cborRead($bytes, $pos);
                    $v       = $this->cborRead($bytes, $pos);
                    $map[$k] = $v;
                }

                return $map;
            })(),
            default => null,
        };
    }

    // ════════════════════════════════════════════════════════════════
    //  VÉRIFICATION DE SIGNATURE COSE
    // ════════════════════════════════════════════════════════════════

    private function verifyCoseSignature(string $data, string $sig, array $coseKey): bool
    {
        $alg = (int) ($coseKey[3] ?? 0);

        return match ($alg) {
            -7   => $this->verifyES256($data, $sig, $coseKey),
            -257 => $this->verifyRS256($data, $sig, $coseKey),
            default => false,
        };
    }

    /** ES256 — ECDSA P-256 + SHA-256 (YubiKey, TouchID, Android) */
    private function verifyES256(string $data, string $sig, array $coseKey): bool
    {
        $x = $coseKey[-2] ?? null;
        $y = $coseKey[-3] ?? null;
        if (! is_string($x) || ! is_string($y)) {
            return false;
        }

        $point = "\x04" . $x . $y;
        $oidEc   = "\x2a\x86\x48\xce\x3d\x02\x01";
        $oidP256 = "\x2a\x86\x48\xce\x3d\x03\x01\x07";

        $algId  = "\x30" . $this->derLen(strlen($oidEc) + 2 + strlen($oidP256) + 2)
                . "\x06" . $this->derLen(strlen($oidEc)) . $oidEc
                . "\x06" . $this->derLen(strlen($oidP256)) . $oidP256;
        $bitStr = "\x03" . $this->derLen(strlen($point) + 1) . "\x00" . $point;
        $spki   = "\x30" . $this->derLen(strlen($algId) + strlen($bitStr)) . $algId . $bitStr;

        $pem    = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
        $pubKey = openssl_pkey_get_public($pem);

        return $pubKey && 1 === openssl_verify($data, $sig, $pubKey, OPENSSL_ALGO_SHA256);
    }

    /** RS256 — RSA PKCS#1 v1.5 + SHA-256 (Windows Hello) */
    private function verifyRS256(string $data, string $sig, array $coseKey): bool
    {
        $n = $coseKey[-1] ?? null;
        $e = $coseKey[-2] ?? null;
        if (! is_string($n) || ! is_string($e)) {
            return false;
        }

        if (ord($n[0]) >= 0x80) {
            $n = "\x00" . $n;
        }
        $nDer = "\x02" . $this->derLen(strlen($n)) . $n;
        $eDer = "\x02" . $this->derLen(strlen($e)) . $e;
        $seq  = "\x30" . $this->derLen(strlen($nDer) + strlen($eDer)) . $nDer . $eDer;

        $bitStr = "\x03" . $this->derLen(strlen($seq) + 1) . "\x00" . $seq;
        $oidRsa = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
        $algId  = "\x30" . $this->derLen(strlen($oidRsa) + 2 + 2)
                . "\x06" . $this->derLen(strlen($oidRsa)) . $oidRsa
                . "\x05\x00";
        $spki   = "\x30" . $this->derLen(strlen($algId) + strlen($bitStr)) . $algId . $bitStr;

        $pem    = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($spki), 64, "\n") . "-----END PUBLIC KEY-----\n";
        $pubKey = openssl_pkey_get_public($pem);

        return $pubKey && 1 === openssl_verify($data, $sig, $pubKey, OPENSSL_ALGO_SHA256);
    }

    private function derLen(int $len): string
    {
        if ($len < 128) {
            return chr($len);
        }
        if ($len < 256) {
            return "\x81" . chr($len);
        }

        return "\x82" . chr(($len >> 8) & 0xFF) . chr($len & 0xFF);
    }

    // ════════════════════════════════════════════════════════════════
    //  ORIGINE
    // ════════════════════════════════════════════════════════════════

    /**
     * Accepte l'origine configurée + localhost sur n'importe quel port en dev.
     * Refuse toujours 127.0.0.1 (IP bloquée par la spec WebAuthn).
     */
    private function originOk(string $origin): bool
    {
        if (self::ORIGIN === $origin) {
            return true;
        }
        // Fallback dev : accepter localhost HTTP/HTTPS sur tout port
        $p = parse_url($origin);

        return false !== $p && ($p['host'] ?? '') === 'localhost';
    }

    // ════════════════════════════════════════════════════════════════
    //  BASE64URL
    // ════════════════════════════════════════════════════════════════

    private function b64uEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private function b64uDecode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
    }
}
