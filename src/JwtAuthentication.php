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

namespace Tuupola\Middleware;

use DomainException;
use Firebase\JWT\Key;
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
use Tuupola\Http\Factory\ResponseFactory;
use Tuupola\Middleware\JwtAuthentication\JwtAuthOptions;
use Tuupola\Middleware\JwtAuthentication\RequestMethodRule;
use Tuupola\Middleware\JwtAuthentication\RequestPathRule;
use Tuupola\Middleware\JwtAuthentication\RuleInterface;

final class JwtAuthentication implements MiddlewareInterface
{
    use DoublePassTrait;

    /**
     * PSR-3 compliant logger.
     */
    private ?LoggerInterface $logger;

    /**
     * Last error message.
     */
    private string $message;

    /**
     * The rules stack.
     * @var SplStack<RuleInterface>
     */
    private SplStack $rules;

    private JwtAuthOptions $options;

    public function __construct(JwtAuthOptions $options, ?LoggerInterface $logger = null)
    {
        /* Setup stack for rules */
        $this->rules = new SplStack;

        $this->logger = $logger;

        $this->options = $options->bindToAuthentication($this);

        /* If nothing was passed in options add default rules. */
        /* This also means $options->rules overrides $options->path */
        /* and $options->ignore */
        if (!count($options->rules)) {
            $this->rules->push(new RequestMethodRule([
                "ignore" => ["OPTIONS"]
            ]));
            $this->rules->push(new RequestPathRule([
                "path" => $this->options->path,
                "ignore" => $this->options->ignore
            ]));
        } else {
            $this->rules($options->rules);
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
        if ("https" !== $scheme && $this->options->secure) {
            if (!in_array($host, $this->options->relaxed)) {
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
                "uri" => (string) $request->getUri()
            ]);
        }

        $params = [
            "decoded" => $decoded,
            "token" => $token,
        ];

        /* Add decoded token to request as attribute when requested. */
        if ($this->options->attribute) {
            $request = $request->withAttribute($this->options->attribute, $decoded);
        }

        /* Modify $request before calling next middleware. */
        $beforeRequest = $this->options->onBeforeCallable($request, $params);

        if ($beforeRequest instanceof ServerRequestInterface) {
            $request = $beforeRequest;
        }

        /* Everything ok, call next middleware. */
        $response = $handler->handle($request);

        /* Modify $response before returning. */
        $afterResponse = $this->options->onAfterCallable($response, $params);

        if ($afterResponse) {
            return $afterResponse;
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
        $new->rules = new SplStack;
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
            if (!$callable($request)) {
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
        return $this->options->onError($response, $arguments) ?? $response;
    }

    /**
     * Fetch the access token.
     */
    private function fetchToken(ServerRequestInterface $request): string
    {
        /* Check for token in header. */
        $header = $request->getHeaderLine($this->options->header);

        if (!empty($header)) {
            if (preg_match($this->options->regexp, $header, $matches)) {
                $this->log(LogLevel::DEBUG, "Using token from request header");
                return $matches[1];
            }
        }

        /* Token not found in header try a cookie. */
        $cookieParams = $request->getCookieParams();

        if (isset($cookieParams[$this->options->cookie])) {
            $this->log(LogLevel::DEBUG, "Using token from cookie");
            if (preg_match($this->options->regexp, $cookieParams[$this->options->cookie], $matches)) {
                return $matches[1];
            }
            return $cookieParams[$this->options->cookie];
        }

        /* If everything fails log and throw. */
        $this->log(LogLevel::WARNING, "Token not found");

        throw new RuntimeException("Token not found.");
    }

    private function decodeToken(string $token): array
    {
        try {
            $algo = $this->options->algorithm;

            $key = new Key(
                $this->options->secret,
                $algo
            );

            $decoded = JWT::decode(
                $token,
                $key
            );

            return (array) $decoded;
        } catch (Exception $exception) {
            $this->log(LogLevel::WARNING, $exception->getMessage(), [$token]);

            throw $exception;
        }
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
