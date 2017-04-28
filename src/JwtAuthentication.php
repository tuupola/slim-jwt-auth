<?php

/*
 * This file is part of PSR-7 JSON Web Token Authentication middleware
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

namespace Tuupola\Middleware;

use Tuupola\Middleware\JwtAuthentication\RequestMethodRule;
use Tuupola\Middleware\JwtAuthentication\RequestPathRule;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Firebase\JWT\JWT;

class JwtAuthentication
{
    /**
     * PSR-3 compliant logger
     */
    protected $logger;

    /**
     * Last error message
     */
    protected $message;

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
        "passthrough" => null,
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
            $this->addRule(new RequestMethodRule([
                "passthrough" => ["OPTIONS"]
            ]));
        }

        /* If path was given in easy mode add rule for it. */
        if (null !== ($this->options["path"])) {
            $this->addRule(new RequestPathRule([
                "path" => $this->options["path"],
                "passthrough" => $this->options["passthrough"]
            ]));
        }
    }

    /**
     * Call the middleware
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param callable $next
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke(RequestInterface $request, ResponseInterface $response, callable $next)
    {
        $scheme = $request->getUri()->getScheme();
        $host = $request->getUri()->getHost();

        /* If rules say we should not authenticate call next and return. */
        if (false === $this->shouldAuthenticate($request)) {
            return $next($request, $response);
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
            return $this->processError($request, $response, [
                "message" => $this->message
            ])->withStatus(401);
        }

        /* If token cannot be decoded return with 401 Unauthorized. */
        if (false === $decoded = $this->decodeToken($token)) {
            return $this->processError($request, $response, [
                "message" => $this->message,
                "token" => $token
            ])->withStatus(401);
        }

        $params = ["decoded" => $decoded];

        /* Add decoded token to request as attribute when requested. */
        if ($this->options["attribute"]) {
            $request = $request->withAttribute($this->options["attribute"], $decoded);
        }

        /* Modify $request before calling next middleware. */
        if (is_callable($this->options["before"])) {
            $before_request = $this->options["before"]($request, $response, $params);
            if ($before_request instanceof \Psr\Http\Message\RequestInterface) {
                $request = $before_request;
            }
        }

        /* Everything ok, call next middleware. */
        $response = $next($request, $response);

        /* Modify $response before returning. */
        if (is_callable($this->options["after"])) {
            $after_response = $this->options["after"]($request, $response, $params);
            if ($after_response instanceof \Psr\Http\Message\ResponseInterface) {
                return $after_response;
            }
        }

        return $response;
    }

    /**
     * Check if middleware should authenticate
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @return boolean True if middleware should authenticate.
     */
    public function shouldAuthenticate(RequestInterface $request)
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
     * @param \Psr\Http\Message\RequestInterface $request
     * @param \Psr\Http\Message\ResponseInterface $response
     * @param mixed[] $arguments

     * @return \Psr\Http\Message\ResponseInterface
     */
    public function processError(RequestInterface $request, ResponseInterface $response, $arguments)
    {
        if (is_callable($this->options["error"])) {
            $handler_response = $this->options["error"]($request, $response, $arguments);
            if (is_a($handler_response, "\Psr\Http\Message\ResponseInterface")) {
                return $handler_response;
            }
        }
        return $response;
    }

    /**
     * Fetch the access token
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @return string|null Base64 encoded JSON Web Token or null if not found.
     */
    public function fetchToken(RequestInterface $request)
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
     * @param string $$token
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
     * @param string|string[] $passthrough
     * @return self
     */
    private function passthrough($passthrough)
    {
        $this->options["passthrough"] = $passthrough;
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
    private function error($error)
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
    public function rules(array $rules)
    {
        /* Clear the stack */
        unset($this->rules);
        $this->rules = new \SplStack;
        /* Add the rules */
        foreach ($rules as $callable) {
            $this->addRule($callable);
        }
        return $this;
    }

    /**
     * Add rule to the stack
     *
     * @param callable $callable Callable which returns a boolean.
     * @return self
     */
    public function addRule($callable)
    {
        $this->rules->push($callable);
        return $this;
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
     * Set the last error message
     *
     * @param string
     * @return self
     */
    private function message($message)
    {
        $this->message = $message;
        return $this;
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

    private function before($before)
    {
        $this->options["before"] = $before->bindTo($this);
        return $this;
    }

    /**
     * Set the after handler
     *
     * @return self
     */
    private function after($after)
    {
        $this->options["after"] = $after->bindTo($this);
        return $this;
    }
}
