<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use ArrayAccess;
use Firebase\JWT\Key;

use function array_key_first;

class ArrayAccessSecret implements Secret
{
    /** @var array<string, string>  */
    private array $secret;

    /** @param ArrayAccess<string, string> $secret */
    public function __construct(
        ArrayAccess $secret
    ) {
        $secret       = (array) $secret;
        $this->secret = $secret[array_key_first($secret)];
    }

    /** @return array<string, Key>|Key */
    public function __invoke(string $algorithm): array|Key
    {
        $keys = [];

        foreach ($this->secret as $key => $secret) {
            $keys[$key] = new Key($secret, $algorithm);
        }

        return $keys;
    }
}
