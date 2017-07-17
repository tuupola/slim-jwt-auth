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

namespace Tuupola\Middleware;

use Firebase\JWT\JWT;
use Interop\Http\ServerMiddleware\MiddlewareInterface;
use Interop\Http\ServerMiddleware\DelegateInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Tuupola\Http\Factory\ResponseFactory;
use Tuupola\Middleware\JwtAuthentication\CallableDelegate;
use Tuupola\Middleware\JwtAuthentication\RequestMethodRule;
use Tuupola\Middleware\JwtAuthentication\RequestPathRule;

final class JwtAuthentication implements MiddlewareInterface
{
    /**
     * PSR-3 compliant logger
     */
    private $logger;

    /**
     * Last error message
     */
    private $message;

    /**
     * Stores all the options passed to the rule
     */
    private $options = [
        "secure" => true,
        "relaxed" => ["localhost", "127.0.0.1"],
        "algorithm" => ["HS256", "HS512", "HS384"],
        "header" => "Authorization",
        "regexp" => "/Bearer\s+(.*)$/i",
        "cookie" => "token",
        "attribute" => "token",
        "path" => null,
        "ignore" => null,
        "before" => null,
        "after" => null,
        "error" => null
    ];

    /**
     * Create a new middleware instance
     *
     * @param string[] $options
     */
    public function __construct(array $options = [])
    {
        /* Setup stack for rules */
        $this->rules = new \SplStack;

        /* Store passed in options overwriting any defaults. */
        $this->hydrate($options);

        /* If nothing was passed in options add default rules. */
        if (!isset($options["rules"])) {
            $this->rules->push(new RequestMethodRule([
                "ignore" => ["OPTIONS"]
            ]));
        }

        /* If path was given in easy mode add rule for it. */
        if (null !== ($this->options["path"])) {
            $this->rules->push(new RequestPathRule([
                "path" => $this->options["path"],
                "ignore" => $this->options["ignore"]
            ]));
        }
    }


    /**
     * Process a request in PSR-7 style and return a response
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @param callable $next
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, callable $next)
    {
        return $this->process($request, new CallableDelegate($next, $response));
    }


    /**
     * Process a request in PSR-15 style and return a response
     *
     * @param ServerRequestInterface $request
     * @param DelegateInterface $delegate
     * @return ResponseInterface
     */
    public function process(ServerRequestInterface $request, DelegateInterface $delegate)
    {
        $scheme = $request->getUri()->getScheme();
        $host = $request->getUri()->getHost();

        /* If rules say we should not authenticate call next and return. */
        if (false === $this->shouldAuthenticate($request)) {
            return $delegate->process($request);
        }

        /* HTTP allowed only if secure is false or server is in relaxed array. */
        if ("https" !== $scheme && true === $this->options["secure"]) {
            if (!in_array($host, $this->options["relaxed"])) {
                $message = sprintf(
                    "Insecure use of middleware over %s denied by configuration.",
                    strtoupper($scheme)
                );
                throw new \RuntimeException($message);
            }
        }

        /* If token cannot be found return with 401 Unauthorized. */
        if (false === $token = $this->fetchToken($request)) {
            $response = (new ResponseFactory)->createResponse(401);
            return $this->processError($request, $response, [
                "message" => $this->message
            ]);
        }

        /* If token cannot be decoded return with 401 Unauthorized. */
        if (false === $decoded = $this->decodeToken($token)) {
            $response = (new ResponseFactory)->createResponse(401);
            return $this->processError($request, $response, [
                "message" => $this->message,
                "token" => $token
            ]);
        }

        $params = ["decoded" => $decoded];

        /* Add decoded token to request as attribute when requested. */
        if ($this->options["attribute"]) {
            $request = $request->withAttribute($this->options["attribute"], $decoded);
        }

        /* Modify $request before calling next middleware. */
        if (is_callable($this->options["before"])) {
            $response = (new ResponseFactory)->createResponse(200);
            $beforeRequest = $this->options["before"]($request, $response, $params);
            if ($beforeRequest instanceof ServerRequestInterface) {
                $request = $beforeRequest;
            }
        }

        /* Everything ok, call next middleware. */
        $response = $delegate->process($request);

        /* Modify $response before returning. */
        if (is_callable($this->options["after"])) {
            $afterResponse = $this->options["after"]($request, $response, $params);
            if ($afterResponse instanceof ResponseInterface) {
                return $afterResponse;
            }
        }

        return $response;
    }

    /**
     * Check if middleware should authenticate
     *
     * @param ServerRequestInterface $request
     * @return boolean True if middleware should authenticate.
     */
    public function shouldAuthenticate(ServerRequestInterface $request)
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
     * Call the error handler if it exists
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface $response
     * @param mixed[] $arguments

     * @return ResponseInterface
     */
    public function processError(ServerRequestInterface $request, ResponseInterface $response, $arguments)
    {
        if (is_callable($this->options["error"])) {
            $handlerResponse = $this->options["error"]($request, $response, $arguments);
            if ($handlerResponse instanceof ResponseInterface) {
                return $handlerResponse;
            }
        }
        return $response;
    }

    /**
     * Fetch the access token
     *
     * @param ServerRequestInterface $request
     * @return string|null Base64 encoded JSON Web Token or null if not found.
     */
    public function fetchToken(ServerRequestInterface $request)
    {
        $header = "";
        $message = "Using token from request header";

        /* Check for token in header. */
        $headers = $request->getHeader($this->options["header"]);
        $header = isset($headers[0]) ? $headers[0] : "";

        if (preg_match($this->options["regexp"], $header, $matches)) {
            $this->log(LogLevel::DEBUG, $message);
            return $matches[1];
        }

        /* Token not found in header try a cookie. */
        $cookieParams = $request->getCookieParams();

        if (isset($cookieParams[$this->options["cookie"]])) {
            $this->log(LogLevel::DEBUG, "Using token from cookie");
            $this->log(LogLevel::DEBUG, $cookieParams[$this->options["cookie"]]);
            return $cookieParams[$this->options["cookie"]];
        };

        /* If everything fails log and return false. */
        $this->message = "Token not found";
        $this->log(LogLevel::WARNING, $this->message);
        return false;
    }

    /**
     * Decode the token
     *
     * @param string $token
     * @return object|boolean The JWT's payload as a PHP object or false in case of error
     */
    public function decodeToken($token)
    {
        try {
            return JWT::decode(
                $token,
                $this->options["secret"],
                (array) $this->options["algorithm"]
            );
        } catch (\Exception $exception) {
            $this->message = $exception->getMessage();
            $this->log(LogLevel::WARNING, $exception->getMessage(), [$token]);
            return false;
        }
    }

    /**
     * Hydrate options from given array
     *
     * @param array $data Array of options.
     * @return self
     */
    public function hydrate($data = [])
    {
        foreach ($data as $key => $value) {
            /* https://github.com/facebook/hhvm/issues/6368 */
            $key = str_replace(".", " ", $key);
            $method = lcfirst(ucwords($key));
            $method = str_replace(" ", "", $method);
            if (method_exists($this, $method)) {
                /* Try to use setter */
                call_user_func([$this, $method], $value);
            } else {
                /* Or fallback to setting option directly */
                $this->options[$key] = $value;
            }
        }
    }

    /**
     * Set path where middleware should be binded to
     *
     * @param string|string[] $$path
     * @return self
     */
    private function path($path)
    {
        $this->options["path"] = $path;
        return $this;
    }

    /**
     * Set path which middleware ignores
     *
     * @param string|string[] $ignore
     * @return self
     */
    private function ignore($ignore)
    {
        $this->options["ignore"] = $ignore;
        return $this;
    }

    /**
     * Set the cookie name where to search the token from
     *
     * @param string $cookie
     * @return self
     */
    private function cookie($cookie)
    {
        $this->options["cookie"] = $cookie;
        return $this;
    }

    /**
     * Set the secure flag
     *
     * @param boolean $secure
     * @return self
     */
    private function secure($secure)
    {
        $this->options["secure"] = !!$secure;
        return $this;
    }

    /**
     * Set hosts where secure rule is relaxed
     *
     * @param string[] $relaxed
     * @return self
     */
    private function relaxed(array $relaxed)
    {
        $this->options["relaxed"] = $relaxed;
        return $this;
    }

    /**
     * Set the secret key
     *
     * @param string $secret
     * @return self
     */
    private function secret($secret)
    {
        $this->options["secret"] = $secret;
        return $this;
    }

    /**
     * Set the error handler
     *
     * @param callable $error
     * @return self
     */
    private function error(callable $error)
    {
        $this->options["error"] = $error;
        return $this;
    }

    /**
     * Set all rules in the stack
     *
     * @param array $rules
     * @return self
     */
    public function withRules(array $rules)
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
     * Add rule to the stack
     *
     * @param callable $callable Callable which returns a boolean.
     * @return self
     */
    public function addRule(callable $callable)
    {
        $new = clone $this;
        $new->rules = clone $this->rules;
        $new->rules->push($callable);
        return $new;
    }

    /**
     * Set the logger
     *
     * @param \Psr\Log\LoggerInterface $logger
     * @return self
     */
    private function logger(LoggerInterface $logger = null)
    {
        $this->logger = $logger;
        return $this;
    }

    /**
     * Logs with an arbitrary level.
     *
     * @param mixed $level
     * @param string $message
     * @param array $context
     *
     * @return null
     */
    public function log($level, $message, array $context = [])
    {
        if ($this->logger) {
            return $this->logger->log($level, $message, $context);
        }
    }

    /**
     * Set the attribute name used to attach decoded token to request
     *
     * @param string
     * @return self
     */
    private function attribute($attribute)
    {
        $this->options["attribute"] = $attribute;
        return $this;
    }

    /**
     * Set the header where token is searched from
     *
     * @param string
     * @return self
     */
    private function header($header)
    {
        $this->options["header"] = $header;
        return $this;
    }

    /**
     * Set the regexp used to extract token from header or environment
     *
     * @param string
     * @return self
     */
    private function regexp($regexp)
    {
        $this->options["regexp"] = $regexp;
        return $this;
    }

    /**
     * Set the allowed algorithms
     *
     * @param string|string[] $algorithm
     * @return self
     */
    private function algorithm($algorithm)
    {
        $this->options["algorithm"] = $algorithm;
        return $this;
    }

    /**
     * Set the before handler
     *
     * @return self
     */

    private function before(callable $before)
    {
        $this->options["before"] = $before->bindTo($this);
        return $this;
    }

    /**
     * Set the after handler
     *
     * @return self
     */
    private function after(callable $after)
    {
        $this->options["after"] = $after->bindTo($this);
        return $this;
    }
}
