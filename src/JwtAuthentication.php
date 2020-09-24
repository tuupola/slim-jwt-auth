<?php

declare(strict_types=1);

/*

Copyright (c) 2015-2020 Mika Tuupola

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

namespace Tuupola\Middleware;

use Closure;
use DomainException;
use InvalidArgumentException;
use Exception;
use Firebase\JWT\JWT;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use RuntimeException;
use SplStack;
use Tuupola\Middleware\DoublePassTrait;
use Tuupola\Http\Factory\ResponseFactory;
use Tuupola\Middleware\JwtAuthentication\RequestMethodRule;
use Tuupola\Middleware\JwtAuthentication\RequestPathRule;
use Tuupola\Middleware\JwtAuthentication\RuleInterface;

final class JwtAuthentication implements MiddlewareInterface
{
    use DoublePassTrait;

    /**
     * PSR-3 compliant logger.
     * @var LoggerInterface|null
     */
    private $logger;

    /**
     * Last error message.
     * @var string
     */
    private $message;

    /**
     * The rules stack.
     * @var SplStack<RuleInterface>
     */
    private $rules;

    /**
     * Stores all the options passed to the middleware.
     * @var mixed[]
     */
    private $options = [
        "secure" => true,
        "relaxed" => ["localhost", "127.0.0.1"],
        "algorithm" => ["HS256", "HS512", "HS384"],
        "header" => "Authorization",
        "regexp" => "/Bearer\s+(.*)$/i",
        "cookie" => "token",
        "attribute" => "token",
        "path" => "/",
        "ignore" => null,
        "before" => null,
        "after" => null,
        "error" => null
    ];

    /**
     * @param mixed[] $options
     */
    public function __construct(array $options = [])
    {
        /* Setup stack for rules */
        $this->rules = new \SplStack;

        /* Store passed in options overwriting any defaults. */
        $this->hydrate($options);

        /* If nothing was passed in options add default rules. */
        /* This also means $options["rules"] overrides $options["path"] */
        /* and $options["ignore"] */
        if (!isset($options["rules"])) {
            $this->rules->push(new RequestMethodRule([
                "ignore" => ["OPTIONS"]
            ]));
            $this->rules->push(new RequestPathRule([
                "path" => $this->options["path"],
                "ignore" => $this->options["ignore"]
            ]));
        }
    }

    /**
     * Process a request in PSR-15 style and return a response.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $scheme = $request->getUri()->getScheme();
        $host = $request->getUri()->getHost();

        /* If rules say we should not authenticate call next and return. */
        if (false === $this->shouldAuthenticate($request)) {
            return $handler->handle($request);
        }

        /* HTTP allowed only if secure is false or server is in relaxed array. */
        if ("https" !== $scheme && true === $this->options["secure"]) {
            if (!in_array($host, $this->options["relaxed"])) {
                $message = sprintf(
                    "Insecure use of middleware over %s denied by configuration.",
                    strtoupper($scheme)
                );
                throw new RuntimeException($message);
            }
        }

        /* If token cannot be found or decoded return with 401 Unauthorized. */
        try {
            $token = $this->fetchToken($request);
            $decoded = $this->decodeToken($token);
        } catch (RuntimeException | DomainException $exception) {
            $response = (new ResponseFactory)->createResponse(401);
            return $this->processError($response, [
                "message" => $exception->getMessage(),
                "uri" => (string)$request->getUri()
            ]);
        }

        $params = [
            "decoded" => $decoded,
            "token" => $token,
        ];

        /* Add decoded token to request as attribute when requested. */
        if ($this->options["attribute"]) {
            $request = $request->withAttribute($this->options["attribute"], $decoded);
        }

        /* Modify $request before calling next middleware. */
        if (is_callable($this->options["before"])) {
            $response = (new ResponseFactory)->createResponse(200);
            $beforeRequest = $this->options["before"]($request, $params);
            if ($beforeRequest instanceof ServerRequestInterface) {
                $request = $beforeRequest;
            }
        }

        /* Everything ok, call next middleware. */
        $response = $handler->handle($request);

        /* Modify $response before returning. */
        if (is_callable($this->options["after"])) {
            $afterResponse = $this->options["after"]($response, $params);
            if ($afterResponse instanceof ResponseInterface) {
                return $afterResponse;
            }
        }

        return $response;
    }

    /**
     * Set all rules in the stack.
     *
     * @param RuleInterface[] $rules
     */
    public function withRules(array $rules): self
    {
        $new = clone $this;
        /* Clear the stack */
        unset($new->rules);
        $new->rules = new \SplStack;
        /* Add the rules */
        foreach ($rules as $callable) {
            $new = $new->addRule($callable);
        }
        return $new;
    }

    /**
     * Add a rule to the stack.
     */
    public function addRule(callable $callable): self
    {
        $new = clone $this;
        $new->rules = clone $this->rules;
        $new->rules->push($callable);
        return $new;
    }

    /**
     * Check if middleware should authenticate.
     */
    private function shouldAuthenticate(ServerRequestInterface $request): bool
    {
        /* If any of the rules in stack return false will not authenticate */
        foreach ($this->rules as $callable) {
            if (false === $callable($request)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Call the error handler if it exists.
     *
     * @param mixed[] $arguments
     */
    private function processError(ResponseInterface $response, array $arguments): ResponseInterface
    {
        if (is_callable($this->options["error"])) {
            $handlerResponse = $this->options["error"]($response, $arguments);
            if ($handlerResponse instanceof ResponseInterface) {
                return $handlerResponse;
            }
        }
        return $response;
    }

    /**
     * Fetch the access token.
     */
    private function fetchToken(ServerRequestInterface $request): string
    {
        /* Check for token in header. */
        $header = $request->getHeaderLine($this->options["header"]);

        if (false === empty($header)) {
            if (preg_match($this->options["regexp"], $header, $matches)) {
                $this->log(LogLevel::DEBUG, "Using token from request header");
                return $matches[1];
            }
        }

        /* Token not found in header try a cookie. */
        $cookieParams = $request->getCookieParams();

        if (isset($cookieParams[$this->options["cookie"]])) {
            $this->log(LogLevel::DEBUG, "Using token from cookie");
            if (preg_match($this->options["regexp"], $cookieParams[$this->options["cookie"]], $matches)) {
                return $matches[1];
            }
            return $cookieParams[$this->options["cookie"]];
        };

        /* If everything fails log and throw. */
        $this->log(LogLevel::WARNING, "Token not found");
        throw new RuntimeException("Token not found.");
    }

    /**
     * Decode the token.
     *
     * @return mixed[]
     */
    private function decodeToken(string $token): array
    {
        try {
            $decoded = JWT::decode(
                $token,
                $this->options["secret"],
                (array) $this->options["algorithm"]
            );
            return (array) $decoded;
        } catch (Exception $exception) {
            $this->log(LogLevel::WARNING, $exception->getMessage(), [$token]);
            throw $exception;
        }
    }

    /**
     * Hydrate options from given array.
     *
     * @param mixed[] $data
     */
    private function hydrate(array $data = []): void
    {
        foreach ($data as $key => $value) {
            /* https://github.com/facebook/hhvm/issues/6368 */
            $key = str_replace(".", " ", $key);
            $method = lcfirst(ucwords($key));
            $method = str_replace(" ", "", $method);
            if (method_exists($this, $method)) {
                /* Try to use setter */
                /** @phpstan-ignore-next-line */
                call_user_func([$this, $method], $value);
            } else {
                /* Or fallback to setting option directly */
                $this->options[$key] = $value;
            }
        }
    }

    /**
     * Set path where middleware should bind to.
     *
     * @param string|string[] $path
     */
    private function path($path): void
    {
        $this->options["path"] = (array) $path;
    }

    /**
     * Set path which middleware ignores.
     *
     * @param string|string[] $ignore
     */
    private function ignore($ignore): void
    {
        $this->options["ignore"] = (array) $ignore;
    }

    /**
     * Set the cookie name where to search the token from.
     */
    private function cookie(string $cookie): void
    {
        $this->options["cookie"] = $cookie;
    }

    /**
     * Set the secure flag.
     */
    private function secure(bool $secure): void
    {
        $this->options["secure"] = $secure;
    }

    /**
     * Set hosts where secure rule is relaxed.
     *
     * @param string[] $relaxed
     */
    private function relaxed(array $relaxed): void
    {
        $this->options["relaxed"] = $relaxed;
    }

    /**
     * Set the secret key.
     *
     * @param string|string[] $secret
     */
    private function secret($secret): void
    {
        if (false === is_array($secret) && false === is_string($secret) && ! $secret instanceof \ArrayAccess) {
            throw new InvalidArgumentException(
                'Secret must be either a string or an array of "kid" => "secret" pairs'
            );
        }
        $this->options["secret"] = $secret;
    }

    /**
     * Set the error handler.
     */
    private function error(callable $error): void
    {
        if ($error instanceof Closure) {
            $this->options["error"] = $error->bindTo($this);
        } else {
            $this->options["error"] = $error;
        }
    }

    /**
     * Set the logger.
     */
    private function logger(LoggerInterface $logger = null): void
    {
        $this->logger = $logger;
    }

    /**
     * Logs with an arbitrary level.
     *
     * @param mixed[] $context
     */
    private function log(string $level, string $message, array $context = []): void
    {
        if ($this->logger) {
            $this->logger->log($level, $message, $context);
        }
    }

    /**
     * Set the attribute name used to attach decoded token to request.
     */
    private function attribute(string $attribute): void
    {
        $this->options["attribute"] = $attribute;
    }

    /**
     * Set the header where token is searched from.
     */
    private function header(string $header): void
    {
        $this->options["header"] = $header;
    }

    /**
     * Set the regexp used to extract token from header or environment.
     */
    private function regexp(string $regexp): void
    {
        $this->options["regexp"] = $regexp;
    }

    /**
     * Set the allowed algorithms
     *
     * @param string|string[] $algorithm
     */
    private function algorithm($algorithm): void
    {
        $this->options["algorithm"] = (array) $algorithm;
    }

    /**
     * Set the before handler.
     */

    private function before(callable $before): void
    {
        if ($before instanceof Closure) {
            $this->options["before"] = $before->bindTo($this);
        } else {
            $this->options["before"] = $before;
        }
    }

    /**
     * Set the after handler.
     */
    private function after(callable $after): void
    {
        if ($after instanceof Closure) {
            $this->options["after"] = $after->bindTo($this);
        } else {
            $this->options["after"] = $after;
        }
    }

    /**
     * Set the rules.
     * @param RuleInterface[] $rules
     */
    private function rules(array $rules): void
    {
        foreach ($rules as $callable) {
            $this->rules->push($callable);
        }
    }
}
