<?php

/*
 * This file is part of Slim JSON Web Token Authentication middleware
 *
 * Copyright (c) 2015 Mika Tuupola
 *
 * Licensed under the MIT license:
 *   http://www.opensource.org/licenses/mit-license.php
 *
 * Project home:
 *   https://github.com/tuupola/slim-jwt-auth
 *
 */

namespace Slim\JwtAuthentication\Test;

#use \Slim\Middleware\JwtAuthentication\RequestPathRule;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

use Slim\Http\Request;
use Slim\Http\Response;
use Slim\Http\Uri;
use Slim\Http\Headers;
use Slim\Http\Body;
use Slim\Http\Collection;

use Slim\Middleware\JwtAuthentication;

class JwtBasicAuthenticationTest extends \PHPUnit_Framework_TestCase
{
    /* @codingStandardsIgnoreStart */
    public static $token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBY21lIFRvb3RocGljcyBMdGQiLCJpYXQiOjE0Mjg4MTk5NDEsImV4cCI6MTc0NDM1Mjc0MSwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoic29tZW9uZUBleGFtcGxlLmNvbSIsInNjb3BlIjpbInJlYWQiLCJ3cml0ZSIsImRlbGV0ZSJdfQ.YzPxtyHLqiJMUaPE6DzBonGUyqLlddxIisxSFk2Gk7Y";
    /* @codingStandardsIgnoreEnd */

    public static $token_as_array = [
        "iss" => "Acme Toothpics Ltd",
        "iat" => "1428819941",
        "exp" => "1744352741",
        "aud" => "www.example.com",
        "sub" => "someone@example.com",
        "scope" => ["read", "write", "delete"]
    ];

    public function testShouldBeTrue()
    {
        $this->assertTrue(true);
    }

    public function testShouldReturn401WithoutToken()
    {
        $uri = Uri::createFromString("https://example.com/api");
        $headers = new Headers();
        $cookies = [];
        $server = [];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $response = new Response();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            return $response->write("Foo");
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromEnvironment()
    {
        $uri = Uri::createFromString("https://example.com/api?abc=123");
        $headers = new Headers();
        $cookies = [];
        $server = ["HTTP_AUTHORIZATION" => "Bearer " . self::$token];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $response = new Response();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            return $response->write("Foo");
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromCookie()
    {
        $uri = Uri::createFromString("https://example.com/api?abc=123");
        $headers = new Headers();
        $cookies = ["token" => self::$token];
        $server = [];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $response = new Response();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            return $response->write("Foo");
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn401WithFalseFromCallback()
    {
        $uri = Uri::createFromString("https://example.com/api?abc=123");
        $headers = new Headers();
        $cookies = [];
        $server = ["HTTP_AUTHORIZATION" => "Bearer " . self::$token];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $response = new Response();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "callback" => function ($params) {
                return false;
            }
        ]);

        $next = function (Request $request, Response $response) {
            return $response->write("Foo");
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn200WithOptions()
    {
        $uri = Uri::createFromString("https://example.com/api");
        $headers = new Headers();
        $cookies = [];
        $server = [];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("OPTIONS", $uri, $headers, $cookies, $server, $body);

        $response = new Response();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            return $response->write("Foo");
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn400WithBrokenToken()
    {
        $uri = Uri::createFromString("https://example.com/api?abc=123");
        $headers = new Headers();
        $cookies = [];
        $server = ["HTTP_AUTHORIZATION" => "Bearer broken" . self::$token];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $response = new Response();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            return $response->write("Foo");
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(400, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn200WithoutTokenWithPath()
    {
        $uri = Uri::createFromString("https://example.com/public");
        $headers = new Headers();
        $cookies = [];
        $server = [];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $response = new Response();

        $auth = new JwtAuthentication([
            "path" => "/api",
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            return $response->write("Foo");
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldNotAllowInsecure()
    {
        $this->setExpectedException("RuntimeException");

        $uri = Uri::createFromString("http://example.com/api");
        $headers = new Headers();
        $cookies = [];
        $server = ["HTTP_AUTHORIZATION" => "Bearer " . self::$token];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $response = new Response();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            return $response->write("Foo");
        };

        $response = $auth($request, $response, $next);
    }

    public function testShouldRelaxInsecureInLocalhost()
    {
        $uri = Uri::createFromString("http://localhost/api");
        $headers = new Headers();
        $cookies = [];
        $server = ["HTTP_AUTHORIZATION" => "Bearer " . self::$token];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $response = new Response();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            return $response->write("Foo");
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldFetchTokenFromEnvironment()
    {
        $uri = Uri::createFromString("https://example.com/api");
        $headers = new Headers();
        $cookies = [];
        $server = ["HTTP_BRAWNDO" => "Bearer " . self::$token];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $response = new Response();

        $auth = new JwtAuthentication([
            "environment" => "HTTP_BRAWNDO",
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $this->assertEquals(self::$token, $auth->fetchToken($request));
    }

    public function testShouldCallCallback()
    {
        $uri = Uri::createFromString("https://example.com/api?abc=123");
        $headers = new Headers();
        $cookies = [];
        $server = ["HTTP_AUTHORIZATION" => "Bearer " . self::$token];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $response = new Response();

        $dummy = null;
        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "callback" => function ($request, $response, $arguments) use (&$dummy) {
                $dummy = $arguments["decoded"];
            }
        ]);

        $next = function (Request $request, Response $response) {
            return $response->write("Foo");
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
        $this->assertTrue(is_object($dummy));
        $this->assertEquals(self::$token_as_array, (array)$dummy);
    }

    public function testShouldCallError()
    {
        $uri = Uri::createFromString("https://example.com/api");
        $headers = new Headers();
        $cookies = [];
        $server = [];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $response = new Response();

        $dummy = null;
        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "error" => function ($request, $response, $arguments) use (&$dummy) {
                $dummy = true;
            }
        ]);

        $next = function (Request $request, Response $response) {
            return $response->write("Foo");
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
        $this->assertTrue($dummy);
    }

    public function testShouldCallErrorAndModifyBody()
    {
        $uri = Uri::createFromString("https://example.com/api");
        $headers = new Headers();
        $cookies = [];
        $server = [];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $response = new Response();

        $dummy = null;
        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "error" => function ($request, $response, $arguments) use (&$dummy) {
                $dummy = true;
                return $response->write("Error");
            }
        ]);

        $next = function (Request $request, Response $response) {
            return $response->write("Foo");
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("Error", $response->getBody());
        $this->assertTrue($dummy);
    }

    public function testShouldGetAndSetPath()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setPath("/admin");
        $this->assertEquals("/admin", $auth->getPath());
    }

    public function testShouldGetAndSetSecret()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setSecret("supersecretkeyyoushouldnotcommittogithub");
        $this->assertEquals("supersecretkeyyoushouldnotcommittogithub", $auth->getSecret());
    }

    public function testShouldGetAndSetSecure()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $this->assertTrue($auth->getSecure());
        $auth->setSecure(false);
        $this->assertFalse($auth->getSecure());
    }

    public function testShouldGetAndSetRelaxed()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $relaxed = array("localhost", "dev.example.com");
        $auth->setRelaxed($relaxed);
        $this->assertEquals($relaxed, $auth->getRelaxed());
    }

    public function testShouldGetAndSetEnvironment()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setEnvironment("HTTP_SOMETHING");
        $this->assertEquals("HTTP_SOMETHING", $auth->getEnvironment());
    }

    public function testShouldGetAndSetCookieName()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setCookie("nekot");
        $this->assertEquals("nekot", $auth->getCookie());
    }

    public function testShouldGetAndSetCallback()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setCallback(function ($request, $response, $params) {
            return true;
        });
        $this->assertTrue(is_callable($auth->getCallback()));
    }

    public function testShouldGetAndSetError()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setError(function ($request, $response, $params) {
            return true;
        });
        $this->assertTrue(is_callable($auth->getError()));
    }

    public function testShouldGetAndSetRules()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setRules(array(
            function ($app) {
                return true;
            },
            function ($app) {
                return false;
            }
        ));
        $this->assertEquals(2, count($auth->getRules()));
    }

    public function testShouldSetAndGetLogger()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $logger = new \Psr\Log\NullLogger;
        $auth->setLogger($logger);

        $this->assertInstanceOf("\Psr\Log\NullLogger", $auth->getLogger());
    }

    public function testShouldSLog()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $logger = new \Psr\Log\NullLogger;
        $auth->setLogger($logger);
        $this->assertNull($auth->log(\Psr\Log\LogLevel::WARNING, "Token not found"));
    }
}
