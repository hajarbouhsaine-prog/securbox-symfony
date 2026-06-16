<?php

declare(strict_types=1);

namespace App\Service;

class EncryptionService
{
    public function generateSalt(): string
    {
        return sodium_bin2hex(
            random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES)
        );
    }

    public function deriveKey(string $masterPassword, string $salt): string
    {
        return sodium_crypto_pwhash(
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
            $masterPassword,
            sodium_hex2bin($salt),
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
    }

    public function encrypt(string $data, string $key): array
    {
        $nonce = random_bytes(
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        );

        $encrypted = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $data,
            '',
            $nonce,
            $key
        );

        return [
            'encrypted' => sodium_bin2hex($encrypted),
            'iv'        => sodium_bin2hex($nonce),
        ];
    }

    public function decrypt(
        string $encryptedData,
        string $iv,
        string $key
    ): string {
        $decoded   = sodium_hex2bin($encryptedData);
        $nonce     = sodium_hex2bin($iv);

        $decrypted = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $decoded,
            '',
            $nonce,
            $key
        );

        if (false === $decrypted) {
            throw new \RuntimeException('Déchiffrement échoué — mot de passe maître incorrect ou données corrompues.');
        }

        sodium_memzero($key);

        return $decrypted;
    }

    public function encryptWithAppSecret(string $data, string $appSecret): array
    {
        $key = sodium_crypto_generichash(
            $appSecret,
            '',
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES
        );

        return $this->encrypt($data, $key);
    }

    public function decryptWithAppSecret(string $encryptedData, string $iv, string $appSecret): string
    {
        $key = sodium_crypto_generichash(
            $appSecret,
            '',
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES
        );

        return $this->decrypt($encryptedData, $iv, $key);
    }
}
