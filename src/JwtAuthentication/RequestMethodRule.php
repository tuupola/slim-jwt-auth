<?php

/*
 * This file is part of Slim JSON Web Token Authentication middleware
 *
 * Copyright (c) 2015-2017 Mika Tuupola
 *
 * Licensed under the MIT license:
 *   http://www.opensource.org/licenses/mit-license.php
 *
 * Project home:
 *   https://github.com/tuupola/slim-jwt-auth
 *
 */

namespace Slim\Middleware\JwtAuthentication;

class RequestMethodRule implements RuleInterface
{
    protected $options = array(
        "passthrough" => array("OPTIONS")
    );

    public function __construct($options = array())
    {
        $this->options = array_merge($this->options, $options);
    }

    public function __invoke(\Slim\Slim $app)
    {
        $environment = $app->environment;
        return !in_array($environment["REQUEST_METHOD"], $this->options["passthrough"]);
    }
}
