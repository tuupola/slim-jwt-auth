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

class RequestPathRule implements RuleInterface
{
    protected $options = array(
        "path" => array("/"),
        "passthrough" => array()
    );

    public function __construct($options = array())
    {
        $this->options = array_merge($this->options, $options);
    }

    public function __invoke(\Slim\Slim $app)
    {
        $uri = $app->request->getResourceUri();
        $uri = preg_replace("#/+#", "/", $uri);

        /* If request path is matches passthrough should not authenticate. */
        foreach ((array)$this->options["passthrough"] as $passthrough) {
            $passthrough = rtrim($passthrough, "/");
            if (!!preg_match("@^{$passthrough}(/.*)?$@", $uri)) {
                return false;
            }
        }

        /* Otherwise check if path matches and we should authenticate. */
        foreach ((array)$this->options["path"] as $path) {
            $path = rtrim($path, "/");
            if (!!preg_match("@^{$path}(/.*)?$@", $uri)) {
                return true;
            }
        }
        return false;
    }
}
