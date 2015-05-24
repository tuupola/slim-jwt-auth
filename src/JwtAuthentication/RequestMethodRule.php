<?php

/*
 * This file is part of Slim JSON Web Token Authentication middleware
 *
 * Copyright (c) 2015 Mika Tuupola
 *
 * Licensed under the MIT license:
 *   http://www.opensource.org/licenses/mit-license.php
 *
 * Project home:
 *   https://github.com/tuupola/slim-jwt-auth
 *
 */

namespace Slim\Middleware\JwtAuthentication;

use \Psr\Http\Message\RequestInterface;

class RequestMethodRule implements RuleInterface
{
    protected $options = [
        "passthrough" => ["OPTIONS"]
    ];

    public function __construct(array $options = [])
    {
        $this->options = array_merge($this->options, $options);
    }

    public function __invoke(RequestInterface $request)
    {
        return !in_array($request->getMethod(), $this->options["passthrough"]);
    }
}
