<?php
/**
 * This file is part of PSR-7 JSON Web Token Authentication middleware & created by Mohammed EL b=BANYAOUI
 *
 * Copyright (c) 2015-2016 Mika Tuupola
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

class RequestMethodPathRule implements RuleInterface
{
    /**
     * Stores all the options passed to the rule
     */
    protected $options = [
        'path' => ['/'],
        'passthrough' => [
            'OPTIONS' => '/'
        ]
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
     * Rules to decide by HTTP verb and request path whether or not the request should be authenticated
     *
     * @param \Psr\Http\Message\RequestInterface $request
     *
     * @return boolean
     */
    public function __invoke(RequestInterface $request)
    {
        $uri    = "/" . $request->getUri()->getPath();
        $uri    = str_replace("//", "/", $uri);
        $method = $request->getMethod();
        /* If request method (or lack of) and path matches passthrough we should not authenticate. */
        foreach ((array) $this->options["passthrough"] as $passthroughMethod => $passthroughPath) {
            $passthroughPath = rtrim($passthroughPath, "/");
            if (!!preg_match("@^{$passthroughPath}(/.*)?$@", $uri) && ($passthroughMethod === $method || is_numeric($passthroughMethod))) {
                return false;
            }
        }
        /* Otherwise check if method (or lack of) and path matches and we should authenticate. */
        foreach ((array) $this->options["path"] as $pathMethod => $pathPath) {
            $pathPath = rtrim($pathPath, "/");
            if (!!preg_match("@^{$pathPath}(/.*)?$@", $uri) && ($pathMethod === $method || is_numeric($pathMethod))) {
                return true;
            }
        }
        return false;
    }
}