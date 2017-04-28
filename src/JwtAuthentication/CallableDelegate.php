<?php

/**
 * This file is part of PSR-7 & PSR-15 JWT Authentication middleware
 *
 * Copyright (c) 2015-2017 Mika Tuupola
 *
 * Licensed under the MIT license:
 *   http://www.opensource.org/licenses/mit-license.php
 *
 * Project home:
 *   https://github.com/tuupola/slim-jwt-auth
 *   https://appelsiini.net/projects/slim-jwt-auth
 *
 */

namespace Tuupola\Middleware\JwtAuthentication;

use Interop\Http\ServerMiddleware\DelegateInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class CallableDelegate implements DelegateInterface
{
    private $callable;
    private $response;

    public function __construct(callable $callable, ResponseInterface $response)
    {
        $this->callable = $callable;
        $this->response = $response;
    }

    public function process(ServerRequestInterface $request)
    {
        $callable = $this->callable;
        return $callable($request, $this->response);
    }
}
