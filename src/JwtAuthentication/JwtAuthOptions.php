<?php

declare(strict_types=1);

/*

Copyright (c) 2015-2022 Mika Tuupola

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

/**
 * @see       https://github.com/tuupola/slim-jwt-auth
 * @see       https://appelsiini.net/projects/slim-jwt-auth
 * @license   https://www.opensource.org/licenses/mit-license.php
 */

namespace Tuupola\Middleware\JwtAuthentication;

use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Tuupola\Middleware\JwtAuthentication;

/**
 * This class stores all the options passed to the middleware.
 */
class JwtAuthOptions
{
    public string $secret;

    public bool $secure;

    /** @var array<string> */
    public array $relaxed;
    public string $algorithm;
    public string $header;
    public string $regexp;
    public string $cookie;
    public string $attribute;
    /** @var array<string> */
    public array $path;

    /** @var RuleInterface[] $rules */
    public array $rules;

    /** @var array<string> */
    public array $ignore;
    public ?\Closure $before;
    public ?\Closure $after;
    public ?\Closure $error;

    private JwtAuthentication $jwtAuthentication;

    public function __construct(
        string $secret,
        bool $secure = true,
        array $relaxed = ["localhost", "127.0.0.1"],
        string $algorithm = "HS256",
        string $header = "Authorization",
        string $regexp = "/Bearer\s+(.*)$/i",
        string $cookie = "token",
        string $attribute = "token",
        array $path = ["/"],
        array $ignore = [],
        array $rules = [],
        ?callable $before = null,
        ?callable $after = null,
        ?callable $error = null
    ) {
        $this->secret = $this->checkSecret($secret);
        $this->secure = $secure;
        $this->relaxed = $relaxed;
        $this->algorithm = $algorithm;
        $this->header = $header;
        $this->regexp = $regexp;
        $this->cookie = $cookie;
        $this->attribute = $attribute;
        $this->path = $path;
        $this->rules = $rules;
        $this->ignore = $ignore;
        $this->before = $before;
        $this->after = $after;
        $this->error = $error;
    }

    private function checkSecret($secret): string
    {
        if (false === is_array($secret) && false === is_string($secret) && !$secret instanceof \ArrayAccess) {
            throw new InvalidArgumentException(
                'Secret must be either a string or an array of "kid" => "secret" pairs'
            );
        }
        return $secret;
    }

    public function bindToAuthentication(JwtAuthentication $target): self
    {
        $this->jwtAuthentication = $target;

        return $this;
    }

    /**
     * Set the error handler.
     */
    public function onError(ResponseInterface $response, array $arguments): ?ResponseInterface
    {
        return $this->error?->call($this->jwtAuthentication, $response, $arguments);
    }

    /**
     * Set the before handler.
     */

    public function onBeforeCallable(ServerRequestInterface $request, array $params): ?ServerRequestInterface
    {
        return $this->before?->call($this->jwtAuthentication, $request, $params);
    }
    /**
     * Set the after handler.
     */
    public function onAfterCallable(ResponseInterface $response, array $params): ?ResponseInterface
    {
        return $this->before?->call($this->jwtAuthentication, $response, $params);
    }
}
