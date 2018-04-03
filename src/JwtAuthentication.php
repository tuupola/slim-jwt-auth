<?php

/*
 * This file is part of PSR-7 JSON Web Token Authentication middleware
 *
 * Copyright (c) 2015-2018 Mika Tuupola
 *
 * Licensed under the MIT license:
 *   http://www.opensource.org/licenses/mit-license.php
 *
 * Project home:
 *   https://github.com/tuupola/slim-jwt-auth
 *
 */

namespace Slim\Middleware;

use Slim\Middleware\JwtAuthentication\RequestMethodRule;
use Slim\Middleware\JwtAuthentication\RequestPathRule;
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
        "environment" => ["HTTP_AUTHORIZATION", "REDIRECT_HTTP_AUTHORIZATION"],
        "algorithm" => ["HS256", "HS512", "HS384"],
        "header" => "Authorization",
        "regexp" => "/Bearer\s+(.*)$/i",
        "cookie" => "token",
        "attribute" => "token",
        "path" => null,
        "passthrough" => null,
        "callback" => null,
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
            return $this->error($request, $response->withStatus(401), [
                "message" => $this->message
            ]);
        }

        /* If token cannot be decoded return with 401 Unauthorized. */
        if (false === $decoded = $this->decodeToken($token)) {
            return $this->error($request, $response->withStatus(401), [
                "message" => $this->message,
                "token" => $token
            ]);
        }

        /* If callback returns false return with 401 Unauthorized. */
        if (is_callable($this->options["callback"])) {
            $params = ["decoded" => $decoded, "token" => $token];
            if (false === $this->options["callback"]($request, $response, $params)) {
                return $this->error($request, $response->withStatus(401), [
                    "message" => $this->message ? $this->message : "Callback returned false"
                ]);
            }
        }

        /* Add decoded token to request as attribute when requested. */
        if ($this->options["attribute"]) {
            $request = $request->withAttribute($this->options["attribute"], $decoded);
        }

        /* Everything ok, call next middleware and return. */
        return $next($request, $response);
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
    public function error(RequestInterface $request, ResponseInterface $response, $arguments)
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
        /* If using PHP in CGI mode and non standard environment */
        $server_params = $request->getServerParams();
        $header = "";
        $message = "";

        /* Check for each given environment */
        foreach ((array) $this->options["environment"] as $environment) {
            if (isset($server_params[$environment])) {
                $message = "Using token from environment";
                $header = $server_params[$environment];
            }
        }

        /* Nothing in environment, try header instead */
        if (empty($header)) {
            $message = "Using token from request header";
            $headers = $request->getHeader($this->options["header"]);
            $header = isset($headers[0]) ? $headers[0] : "";
        }

        /* Try apache_request_headers() as last resort */
        if (empty($header) && function_exists("apache_request_headers")) {
            $message = "Using token from apache_request_headers()";
            $headers = apache_request_headers();
            $header = isset($headers[$this->options["header"]]) ? $headers[$this->options["header"]] : "";
        }

        if (preg_match($this->options["regexp"], $header, $matches)) {
            $this->log(LogLevel::DEBUG, $message);
            return $matches[1];
        }

        /* Bearer not found, try a cookie. */
        $cookie_params = $request->getCookieParams();

        if (isset($cookie_params[$this->options["cookie"]])) {
            $this->log(LogLevel::DEBUG, "Using token from cookie");
            $this->log(LogLevel::DEBUG, $cookie_params[$this->options["cookie"]]);
            return $cookie_params[$this->options["cookie"]];
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
     * Hydate options from given array
     *
     * @param array $data Array of options.
     * @return self
     */
    private function hydrate(array $data = [])
    {
        foreach ($data as $key => $value) {
            $method = "set" . ucfirst($key);
            if (method_exists($this, $method)) {
                call_user_func(array($this, $method), $value);
            }
        }
        return $this;
    }


    /**
     * Get path where middleware is be binded to
     *
     * @return string
     */
    public function getPath()
    {
        return $this->options["path"];
    }

    /**
     * Set path where middleware should be binded to
     *
     * @param string|string[] $$path
     * @return self
     */
    public function setPath($path)
    {
        $this->options["path"] = $path;
        return $this;
    }

    /**
     * Get path which middleware ignores
     *
     * @return string|array
     */
    public function getPassthrough()
    {
        return $this->options["passthrough"];
    }

    /**
     * Set path which middleware ignores
     *
     * @param string|string[] $passthrough
     * @return self
     */
    public function setPassthrough($passthrough)
    {
        $this->options["passthrough"] = $passthrough;
        return $this;
    }

    /**
     * Get the environment name where to search the token from
     *
     * @return string Name of environment variable.
     */
    public function getEnvironment()
    {
        return $this->options["environment"];
    }

    /**
     * Set the environment name where to search the token from
     *
     * @param string $environment
     * @return self
     */
    public function setEnvironment($environment)
    {
        $this->options["environment"] = $environment;
        return $this;
    }

    /**
     * Get the cookie name where to search the token from
     *
     * @return string
     */
    public function getCookie()
    {
        return $this->options["cookie"];
    }

    /**
     * Set the cookie name where to search the token from
     *
     * @param string $cookie
     * @return self
     */
    public function setCookie($cookie)
    {
        $this->options["cookie"] = $cookie;
        return $this;
    }

    /**
     * Get the secure flag
     *
     * @return boolean
     */
    public function getSecure()
    {
        return $this->options["secure"];
    }

    /**
     * Set the secure flag
     *
     * @param boolean $secure
     * @return self
     */
    public function setSecure($secure)
    {
        $this->options["secure"] = !!$secure;
        return $this;
    }


    /**
     * Get hosts where secure rule is relaxed
     *
     * @return array
     */
    public function getRelaxed()
    {
        return $this->options["relaxed"];
    }

    /**
     * Set hosts where secure rule is relaxed
     *
     * @param string[] $relaxed
     * @return self
     */
    public function setRelaxed(array $relaxed)
    {
        $this->options["relaxed"] = $relaxed;
        return $this;
    }

    /**
     * Get the secret key
     *
     * @return string
     */
    public function getSecret()
    {
        return $this->options["secret"];
    }

    /**
     * Set the secret key
     *
     * @param string $secret
     * @return self
     */
    public function setSecret($secret)
    {
        $this->options["secret"] = $secret;
        return $this;
    }

    /**
     * Get the callback
     *
     * @return callable
     */
    public function getCallback()
    {
        return $this->options["callback"];
    }

    /**
     * Set the callback
     *
     * @param callable $callback
     * @return self
     */
    public function setCallback($callback)
    {
        $this->options["callback"] = $callback->bindTo($this);
        return $this;
    }

    /**
     * Get the error handler
     *
     * @return callable
     */
    public function getError()
    {
        return $this->options["error"];
    }

    /**
     * Set the error handler
     *
     * @param callable $error
     * @return self
     */
    public function setError($error)
    {
        $this->options["error"] = $error;
        return $this;
    }

    /**
     * Get the rules stack
     *
     * @return \SplStack
     */
    public function getRules()
    {
        return $this->rules;
    }

    /**
     * Set all rules in the stack
     *
     * @param array $rules
     * @return self
     */
    public function setRules(array $rules)
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

    /* Cannot use traits since PHP 5.3 should be supported */

    /**
     * Get the logger
     *
     * @return \Psr\Log\LoggerInterface $logger
     */
    public function getLogger()
    {
        return $this->logger;
    }

    /**
     * Set the logger
     *
     * @param \Psr\Log\LoggerInterface $logger
     * @return self
     */
    public function setLogger(LoggerInterface $logger = null)
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
     * Get last error message
     *
     * @return string
     */
    public function getMessage()
    {
        return $this->message;
    }

    /**
     * Set the last error message
     *
     * @param string
     * @return self
     */
    public function setMessage($message)
    {
        $this->message = $message;
        return $this;
    }

    /**
     * Get the attribute name used to attach decoded token to request
     *
     * @return string
     */
    public function getAttribute()
    {
        return $this->options["attribute"];
    }

    /**
     * Set the attribute name used to attach decoded token to request
     *
     * @param string
     * @return self
     */
    public function setAttribute($attribute)
    {
        $this->options["attribute"] = $attribute;
        return $this;
    }

    /**
     * Get the header where token is searched from
     *
     * @return string
     */
    public function getHeader()
    {
        return $this->options["header"];
    }

    /**
     * Set the header where token is searched from
     *
     * @param string
     * @return self
     */
    public function setHeader($header)
    {
        $this->options["header"] = $header;
        return $this;
    }

    /**
     * Get the regexp used to extract token from header or environment
     *
     * @return string
     */
    public function getRegexp()
    {
        return $this->options["regexp"];
    }

    /**
     * Set the regexp used to extract token from header or environment
     *
     * @param string
     * @return self
     */
    public function setRegexp($regexp)
    {
        $this->options["regexp"] = $regexp;
        return $this;
    }

    /**
     * Get the allowed algorithms
     *
     * @return string|string[]
     */
    public function getAlgorithm()
    {
        return $this->options["algorithm"];
    }

    /**
     * Set the allowed algorithms
     *
     * @param string|string[] $algorithm
     * @return self
     */
    public function setAlgorithm($algorithm)
    {
        $this->options["algorithm"] = $algorithm;
        return $this;
    }
}
