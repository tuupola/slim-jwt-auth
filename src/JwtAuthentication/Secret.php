<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Firebase\JWT\Key;

interface Secret
{
    /** @return array<string, Key>|Key */
    public function __invoke(string $algorithm): array|Key;
}
