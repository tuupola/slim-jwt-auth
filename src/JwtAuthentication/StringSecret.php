<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Firebase\JWT\Key;

class StringSecret implements Secret
{
    public function __construct(
        private readonly string $secret
    ) {
    }

    /** @return array<string, Key>|Key */
    public function __invoke(string $algorithm): array|Key
    {
        return new Key($this->secret, $algorithm);
    }
}
