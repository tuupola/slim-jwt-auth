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
 */

namespace Tuupola\Middleware;

use Firebase\JWT\JWT;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use RuntimeException;
use Throwable;

use function array_key_exists;
use function in_array;
use function preg_match;
use function sprintf;
use function strtoupper;

final class JwtAuthentication implements MiddlewareInterface
{
    private readonly LoggerInterface $logger;

    public function __construct(
        private readonly JwtAuthenticationOption $options,
        ?LoggerInterface $logger = null
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    public function __invoke(
        ServerRequestInterface $request,
        ResponseInterface $response,
        callable $next
    ): ResponseInterface {
        return $this->process($request, new CallableHandler($next, $response));
    }

    /**
     * Process a request in PSR-15 style and return a response.
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $scheme = $request->getUri()->getScheme();
        $host   = $request->getUri()->getHost();

        /* HTTP allowed only if secure is false or server is in relaxed array. */
        if ($scheme !== 'https' && $this->options->secure === true && ! in_array($host, $this->options->relaxed)) {
            throw new RuntimeException(sprintf(
                'Insecure use of middleware over %s denied by configuration.',
                strtoupper($scheme),
            ));
        }

        try {
            $token = $this->fetchToken($request);
        } catch (TokenNotFound) {
            return $handler->handle($request);
        }

        try {
            $jwtDecodedToken = $this->decodeToken($token);
        } catch (Throwable) {
            return $handler->handle($request);
        }

        /* Add decoded token to request as attribute when requested. */
        $request = $request->withAttribute($this->options->attribute, $jwtDecodedToken);

        /* Modify $request before calling next middleware. */
        $request = $this->options->before->__invoke($request, $jwtDecodedToken);

        /* Everything ok, call next middleware. */
        $response = $handler->handle($request);

        /* Modify $response before returning. */
        return $this->options->after->__invoke($response, $jwtDecodedToken);
    }

    /**
     * Fetch the access token.
     */
    private function fetchToken(ServerRequestInterface $request): string
    {
        /* Check for token in header. */
        $header = $request->getHeaderLine($this->options->header);

        if (empty($header) === false) {
            if (preg_match($this->options->regexp, $header, $matches)) {
                $this->logger->debug('Using token from request header');

                return $matches[1];
            }
        }

        /* Token not found in header try a cookie. */
        $cookieParams = $request->getCookieParams();

        if (array_key_exists($this->options->cookie, $cookieParams)) {
            $this->logger->debug('Using token from cookie');
            if (preg_match($this->options->regexp, $cookieParams[$this->options->cookie], $matches)) {
                return $matches[1];
            }

            return $cookieParams[$this->options->cookie];
        }

        /* If everything fails log and throw. */
        $this->logger->debug('Token not found');

        throw TokenNotFound::create();
    }

    /**
     * Decode the token.
     */
    private function decodeToken(string $token): JwtDecodedToken
    {
        try {
            $decoded = JWT::decode(
                $token,
                $this->options->secret->__invoke($this->options->algorithm),
            );

            return new JwtDecodedToken((array) $decoded, $token);
        } catch (Throwable $exception) {
            $this->logger->warning($exception->getMessage(), [$token]);

            throw $exception;
        }
    }
}
