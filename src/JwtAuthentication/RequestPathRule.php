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

use Psr\Http\Message\ServerRequestInterface;

/**
 * Rule to decide by request path whether the request should be authenticated or not.
 */

final class RequestPathRule implements RuleInterface
{
    /**
     * Stores all the options passed to the rule
     */
    private $options = [
        "path" => ["/"],
        "ignore" => []
    ];

    /**
     * Create a new rule instance
     *
     * @param string[] $options
     * @return void
     */
    public function __construct($options = [])
    {
        $this->options = array_merge($this->options, $options);
    }

    /**
     * @param \Psr\Http\Message\ServerRequestInterface $request
     * @return boolean
     */
    public function __invoke(ServerRequestInterface $request)
    {
        $uri = "/" . $request->getUri()->getPath();
        $uri = preg_replace("#/+#", "/", $uri);

        /* If request path is matches ignore should not authenticate. */
        foreach ((array)$this->options["ignore"] as $ignore) {
            $ignore = rtrim($ignore, "/");
            if (!!preg_match("@^{$ignore}(/.*)?$@", $uri)) {
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
