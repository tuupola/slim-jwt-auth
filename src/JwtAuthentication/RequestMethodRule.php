<?php

/**
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

use \Psr\Http\Message\RequestInterface;

/**
 * Rule to decide by HTTP verb whether the request should be authenticated or not.
 */

class RequestMethodRule implements RuleInterface
{

    /**
     * Stores all the options passed to the rule
     */
    protected $options = [
        "passthrough" => ["OPTIONS"]
    ];

    /**
     * Create a new rule instance
     *
     * @param string[] $options
     * @return void
     */
    public function __construct(array $options = [])
    {
        $this->options = array_merge($this->options, $options);
    }

    /**
     * @param \Psr\Http\Message\RequestInterface $request
     * @return boolean
     */
    public function __invoke(RequestInterface $request)
    {
        return !in_array($request->getMethod(), $this->options["passthrough"]);
    }
}
