<?php

declare(strict_types=1);

namespace Tuupola\Middleware;

use SplStack;
use Tuupola\Middleware\JwtAuthentication\NullAfter;
use Tuupola\Middleware\JwtAuthentication\NullBefore;
use Tuupola\Middleware\JwtAuthentication\NullError;
use Tuupola\Middleware\JwtAuthentication\RequestMethodRule;
use Tuupola\Middleware\JwtAuthentication\RequestPathRule;
use Tuupola\Middleware\JwtAuthentication\RuleInterface;
use Tuupola\Middleware\JwtAuthentication\Secret;

class JwtAuthenticationOption
{
    /**
     * The rules stack.
     *
     * @var SplStack<RuleInterface>
     */
    public readonly SplStack $rules;

    /**
     * @param string[] $relaxed
     * @param string[] $path
     * @param string[] $ignore
     */
    private function __construct(
        public readonly Secret $secret,
        public readonly bool $secure,
        public readonly array $relaxed,
        public readonly string $algorithm,
        public readonly string $header,
        public readonly string $regexp,
        public readonly string $cookie,
        public readonly string $attribute,
        public readonly array $path,
        public readonly array $ignore,
        public readonly JwtAuthentificationBefore $before,
        public readonly JwtAuthentificationAfter $after,
        public readonly JwtAuthentificationError $error,
        RuleInterface ...$rules
    ) {
        /** @var SplStack<RuleInterface> */
        $splStack = new SplStack();
        /* Add the rules */
        foreach ($rules as $callable) {
            $splStack->push($callable);
        }

        $this->rules = $splStack;
    }

    public static function create(Secret $secret): self
    {
        return new self(
            $secret,
            true,
            ['localhost', '127.0.0.1'],
            'HS256',
            'Authorization',
            '/Bearer\s+(.*)$/i',
            'token',
            'token',
            ['/'],
            [],
            new NullBefore(),
            new NullAfter(),
            new NullError(),
            new RequestMethodRule(['OPTIONS']),
            new RequestPathRule(['/'], []),
        );
    }

    /**
     * Set the attribute name used to attach decoded token to request.
     */
    public function withAttribute(string $attribute): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $attribute,
            $this->path,
            $this->ignore,
            $this->before,
            $this->after,
            $this->error,
            ...$this->rules,
        );
    }

    /**
     * Set the header where token is searched from.
     */
    public function withHeader(string $header): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->path,
            $this->ignore,
            $this->before,
            $this->after,
            $this->error,
            ...$this->rules,
        );
    }

    /**
     * Set the regexp used to extract token from header or environment.
     */
    public function withRegexp(string $regexp): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $regexp,
            $this->cookie,
            $this->attribute,
            $this->path,
            $this->ignore,
            $this->before,
            $this->after,
            $this->error,
            ...$this->rules,
        );
    }

    /**
     * Set the allowed algorithm
     */
    public function withAlgorithm(string $algorithm): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->path,
            $this->ignore,
            $this->before,
            $this->after,
            $this->error,
            ...$this->rules,
        );
    }

    /**
     * Set the before handler.
     */

    public function withBefore(JwtAuthentificationBefore $before): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->path,
            $this->ignore,
            $before,
            $this->after,
            $this->error,
            ...$this->rules,
        );
    }

    /**
     * Set the after handler.
     */
    public function withAfter(JwtAuthentificationAfter $after): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->path,
            $this->ignore,
            $this->before,
            $after,
            $this->error,
            ...$this->rules,
        );
    }

    /**
     * Set the rules.
     */
    public function withRules(RuleInterface ...$rules): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->path,
            $this->ignore,
            $this->before,
            $this->after,
            $this->error,
            ...$rules,
        );
    }

    /**
     * Set the error handler.
     */
    public function withError(JwtAuthentificationError $error): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->path,
            $this->ignore,
            $this->before,
            $this->after,
            $error,
            ...$this->rules,
        );
    }

    /**
     * Set path where middleware should bind to.
     *
     * @param string[] $path
     */
    public function withPath(array $path): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $path,
            $this->ignore,
            $this->before,
            $this->after,
            $this->error,
            ...$this->rules,
        );
    }

    /**
     * Set path which middleware ignores.
     *
     * @param string[] $ignore
     */
    public function withIgnore(array $ignore): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->path,
            $ignore,
            $this->before,
            $this->after,
            $this->error,
            ...$this->rules,
        );
    }

    /**
     * Set the cookie name where to search the token from.
     */
    public function withCookie(string $cookie): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $cookie,
            $this->attribute,
            $this->path,
            $this->ignore,
            $this->before,
            $this->after,
            $this->error,
            ...$this->rules,
        );
    }

    /**
     * Set the secure flag.
     */
    public function withSecure(bool $secure): self
    {
        return new self(
            $this->secret,
            $secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->path,
            $this->ignore,
            $this->before,
            $this->after,
            $this->error,
            ...$this->rules,
        );
    }

    /**
     * Set hosts where secure rule is relaxed.
     *
     * @param string[] $relaxed
     */
    public function withRelaxed(array $relaxed): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->path,
            $this->ignore,
            $this->before,
            $this->after,
            $this->error,
            ...$this->rules,
        );
    }

    /**
     * Set the secret key.
     */
    public function withSecret(Secret $secret): self
    {
        return new self(
            $secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->path,
            $this->ignore,
            $this->before,
            $this->after,
            $this->error,
            ...$this->rules,
        );
    }

    /**
     * Add a rule to the stack.
     */
    public function addRule(RuleInterface $callable): self
    {
        return new self(
            $this->secret,
            $this->secure,
            $this->relaxed,
            $this->algorithm,
            $this->header,
            $this->regexp,
            $this->cookie,
            $this->attribute,
            $this->path,
            $this->ignore,
            $this->before,
            $this->after,
            $this->error,
            ...[...(array) $this->rules, $callable],
        );
    }
}
