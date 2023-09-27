<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Psr\Http\Message\ServerRequestInterface;

interface JwtAuthentificationBefore
{
    public function __invoke(ServerRequestInterface $request, JwtDecodedToken $jwtDecodedToken): ServerRequestInterface;
}
