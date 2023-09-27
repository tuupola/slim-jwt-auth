<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use RuntimeException;

class TokenNotFound extends RuntimeException
{
    public function __construct(string $message)
    {
        parent::__construct($message);
    }

    public static function create(): self
    {
        return new self('Token not found.');
    }
}
