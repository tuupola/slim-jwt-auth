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

class RequestPathRule implements RuleInterface
{
    protected $options = array(
        "path" => "/"
    );

    public function __construct($options = array())
    {
        $this->options = array_merge($this->options, $options);
    }

    public function __invoke(\Slim\Slim $app)
    {
        $path = rtrim($this->options["path"], "/");
        $regex = "@{$path}(/.*)?$@";
        return !!preg_match($regex, $app->request->getPath());
    }
}
