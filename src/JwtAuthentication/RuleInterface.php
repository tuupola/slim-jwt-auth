<?php

/*
 * This file is part of PSR-7 JSON Web Token Authentication middleware
 *
 * Copyright (c) 2015-2018 Mika Tuupola
 *
 * Licensed under the MIT license:
 *   http://www.opensource.org/licenses/mit-license.php
 *
 * Project home:
 *   https://github.com/tuupola/slim-jwt-auth
 *
 */

namespace Slim\Middleware\JwtAuthentication;

use Psr\Http\Message\RequestInterface;

interface RuleInterface
{
    public function __invoke(RequestInterface $request);
}
