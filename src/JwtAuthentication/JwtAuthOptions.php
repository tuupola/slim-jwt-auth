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
use Tuupola\Middleware\ArrayAccessImpl;
use Tuupola\Middleware\JwtAuthentication;

/**
 * This class stores all the options passed to the middleware.
 */
class JwtAuthOptions
{
    /** @var array|ArrayAccessImpl */
    public $secret;
    /** @var array|ArrayAccessImpl */
    public $algorithm;

    public bool $secure;

    /** @var array<string> */
    public array $relaxed;

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
    public $before;
    public $after;
    public $error;

    private JwtAuthentication $jwtAuthentication;

    public function __construct(
        /** @var string|array|ArrayAccessImpl */
        $secret,
        /** @var string|array|ArrayAccessImpl */
        $algorithm = "HS256",
        bool $secure = true,
        array $relaxed = ["localhost", "127.0.0.1"],
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
        $this->algorithm = $this->applyAlgorithm($this->secret, $algorithm);
        $this->secure = $secure;
        $this->relaxed = $relaxed;
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

    public static function fromArray(array $data): self
    {
        $values = [
            "secret" => "",
            "algorithm" => "HS256",
            "secure" => true,
            "relaxed" => ["localhost", "127.0.0.1"],
            "header" => "Authorization",
            "regexp" => "/Bearer\s+(.*)$/i",
            "cookie" => "token",
            "attribute" => "token",
            "path" => ["/"],
            "ignore" => [],
            "rules" => [],
            "before" => null,
            "after" => null,
            "error" => null
        ];
        $inArray = [];

        foreach ($values as $key => $value) {
            $inArray[$key] = $data[$key] ?? $value;
        }

        return new self(...$inArray);
    }

    public function bindToAuthentication(JwtAuthentication $target): self
    {
        $this->jwtAuthentication = $target;

        $this->error = $this->bindClosure($this->error, $target);
        $this->before = $this->bindClosure($this->before, $target);
        $this->after = $this->bindClosure($this->after, $target);

        return $this;
    }

    /**
     * Set the error handler.
     */
    public function onError(ResponseInterface $response, array $arguments): ?ResponseInterface
    {
        $func = $this->error;

        return is_null($func) ? null : $func($response, $arguments);
    }

    /**
     * Set the before handler.
     */
    public function onBeforeCallable(ServerRequestInterface $request, array $params): ?ServerRequestInterface
    {
        $func = $this->before;

        return is_null($func) ? null : $func($request, $params);
    }
    /**
     * Set the after handler.
     */
    public function onAfterCallable(ResponseInterface $response, array $params): ?ResponseInterface
    {
        $func = $this->after;

        return is_null($func) ? null : $func($response, $params);
    }

    private function checkSecret($secret): array
    {
        if (!(is_array($secret) || is_string($secret) || $secret instanceof \ArrayAccess)) {
            throw new InvalidArgumentException(
                'Secret must be either a string or an array of "kid" => "secret" pairs'
            );
        }

        return (array) $secret;
    }

    private function applyAlgorithm(array $secret, $algorithm)
    {
        if (is_string($algorithm)) {
            $secretIndex = array_keys($secret);

            return array_fill_keys($secretIndex, $algorithm);
        }

        foreach ($secret as $key => $value) {
            if (!in_array($key, $algorithm)) {
                throw new InvalidArgumentException(
                    "All secrets must have a corresponding algorithm"
                );
            }
        }

        return $algorithm;
    }

    private function bindClosure(?callable $closure, JwtAuthentication $target): ?\Closure
    {
        if ($closure) {
            if ($closure instanceof \Closure) {
                return $closure->bindTo($target);
            }

            return \Closure::fromCallable($closure);
        }

        return null;
    }
}
