<?php

declare(strict_types=1);

namespace Tuupola\Middleware\JwtAuthentication;

use Psr\Http\Message\ServerRequestInterface;
use Tuupola\Middleware\JwtAuthentificationBefore;
use Tuupola\Middleware\JwtDecodedToken;

class NullBefore implements JwtAuthentificationBefore
{
    public function __invoke(ServerRequestInterface $request, JwtDecodedToken $jwtDecodedToken): ServerRequestInterface
    {
        return $request;
    }
}
