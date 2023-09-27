<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use RuntimeException;

use function array_key_exists;
use function is_array;
use function is_string;
use function sprintf;

class JwtDecodedToken
{
    /** @param array<string, mixed> $payload */
    public function __construct(public readonly array $payload, public readonly string $token)
    {
    }

    public function getStringAttribute(string $name): string
    {
        if (! array_key_exists($name, $this->payload)) {
            throw new RuntimeException(sprintf('Attribute `%s` does not exist', $name));
        }

        if (! is_string($this->payload[$name])) {
            throw new RuntimeException(sprintf('Attribute `%s` is not a string', $name));
        }

        return $this->payload[$name];
    }

    /** @return array<int|string, mixed> */
    public function getArrayAttribute(string $name): array
    {
        if (! array_key_exists($name, $this->payload)) {
            throw new RuntimeException(sprintf('Attribute `%s` does not exist', $name));
        }

        if (! is_array($this->payload[$name])) {
            throw new RuntimeException(sprintf('Attribute `%s` is not an array', $name));
        }

        return $this->payload[$name];
    }
}
