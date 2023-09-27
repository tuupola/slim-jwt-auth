<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Firebase\JWT\Key;

class ArrayOfSecret implements Secret
{
    /** @param array<string, string> $secrets */
    public function __construct(
        private readonly array $secrets
    ) {
    }

    /** @return array<string, Key>|Key */
    public function __invoke(string $algorithm): array|Key
    {
        $keys = [];

        foreach ($this->secrets as $key => $secret) {
            $keys[$key] = new Key($secret, $algorithm);
        }

        return $keys;
    }
}
