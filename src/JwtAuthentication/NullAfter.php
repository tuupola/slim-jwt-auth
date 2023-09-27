<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Psr\Http\Message\ResponseInterface;
use Tuupola\Middleware\JwtAuthentificationAfter;
use Tuupola\Middleware\JwtDecodedToken;

class NullAfter implements JwtAuthentificationAfter
{
    public function __invoke(ResponseInterface $response, JwtDecodedToken $jwtDecodedToken): ResponseInterface
    {
        return $response;
    }
}
