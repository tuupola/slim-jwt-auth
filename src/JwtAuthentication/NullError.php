<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use Tuupola\Middleware\JwtAuthentificationError;

class NullError implements JwtAuthentificationError
{
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, Throwable $exception): ResponseInterface
    {
        return $response;
    }
}
