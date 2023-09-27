<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Psr\Http\Message\ResponseInterface;

interface JwtAuthentificationAfter
{
    public function __invoke(ResponseInterface $response, JwtDecodedToken $jwtDecodedToken): ResponseInterface;
}
