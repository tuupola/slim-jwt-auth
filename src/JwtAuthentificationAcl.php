<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Tuupola\Http\Factory\ResponseFactory;

final class JwtAuthentificationAcl implements MiddlewareInterface
{
    public function __construct(
        private readonly JwtAuthenticationOption $options
    ) {
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
        /* If rules say we should not authenticate call next and return. */
        if ($this->shouldAuthenticate($request) === false) {
            return $handler->handle($request);
        }

        if ($request->getAttribute($this->options->attribute) === null) {
            return $this->options->error->__invoke($request, (new ResponseFactory())->createResponse(401), new NotAuthorized());
        }

        return $handler->handle($request);
    }

    /**
     * Check if middleware should authenticate.
     */
    private function shouldAuthenticate(ServerRequestInterface $request): bool
    {
        /* If any of the rules in stack return false will not authenticate */
        foreach ($this->options->rules as $callable) {
            if ($callable($request) === false) {
                return false;
            }
        }

        return true;
    }
}
