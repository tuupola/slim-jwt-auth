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

use \Psr\Http\Message\ServerRequestInterface;

/**
 * Rule to decide by HTTP verb whether the request should be authenticated or not.
 */

final class RequestMethodRule implements RuleInterface
{

    /**
     * Stores all the options passed to the rule
     */
    private $options = [
        "ignore" => ["OPTIONS"]
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
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @return boolean
     */
    public function __invoke(ServerRequestInterface $request)
    {
        return !in_array($request->getMethod(), $this->options["ignore"]);
    }
}
