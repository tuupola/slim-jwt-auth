<?php

/*
 * This file is part of PSR-7 JSON Web Token Authentication middleware
 *
 * Copyright (c) 2015-2017 Mika Tuupola
 *
 * Licensed under the MIT license:
 *   http://www.opensource.org/licenses/mit-license.php
 *
 * Project home:
 *   https://github.com/tuupola/slim-jwt-auth
 *
 */

namespace Slim\Middleware;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

use Zend\Diactoros\ServerRequest as Request;
use Zend\Diactoros\ServerRequestFactory;
use Zend\Diactoros\Response;
use Zend\Diactoros\Uri;

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
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET");
        $response = new Response;

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromEnvironment()
    {
        $request = ServerRequestFactory::fromGlobals(
            ["HTTP_AUTHORIZATION" => "Bearer " . self::$token]
        );
        $request = $request
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET");

        $response = new Response;

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromHeader()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET")
            ->withHeader("X-Token", "Bearer " . self::$token);

        $response = new Response;

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "header" => "X-Token"
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromHeaderWithCustomRegexp()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET")
            ->withHeader("X-Token", self::$token);

        $response = new Response;

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "header" => "X-Token",
            "regexp" => "/(.*)/"
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromCookie()
    {
        $request = ServerRequestFactory::fromGlobals(
            null,
            null,
            null,
            ["token" => self::$token],
            null
        );
        $request = $request
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET");

        $response = new Response;

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn401WithFalseFromCallback()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = new Response;

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "callback" => function ($params) {
                return false;
            }
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturnDefaultMessageWithFalseFromCallback()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = new Response;

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "callback" => function ($params) {
                return false;
            },
            "error" => function (Request $request, Response $response, $arguments) {
                $response->getBody()->write($arguments["message"]);
                return $response;
            }
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("Callback returned false", $response->getBody());
    }

    public function testShouldReturn401WithInvalidAlgorithm()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = new Response;

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "algorithm" => "nosuch"
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn200WithOptions()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("OPTIONS");

        $response = new Response;

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn400WithInvalidToken()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET")
            ->withHeader("Authorization", "Bearer invalid" . self::$token);

        $response = new Response;

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn200WithoutTokenWithPath()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/public"))
            ->withMethod("GET");

        $response = new Response;

        $auth = new JwtAuthentication([
            "path" => ["/api", "/foo"],
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithoutTokenWithPassthrough()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api/ping"))
            ->withMethod("GET");

        $response = new Response;

        $auth = new JwtAuthentication([
            "path" => ["/api", "/foo"],
            "passthrough" => ["/api/ping"],
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldNotAllowInsecure()
    {
        $this->setExpectedException("RuntimeException");

        $request = (new Request)
            ->withUri(new Uri("http://example.com/api"))
            ->withMethod("GET")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = new Response;

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);
    }

    public function testShouldRelaxInsecureInLocalhost()
    {
        $request = (new Request)
            ->withUri(new Uri("http://localhost/api"))
            ->withMethod("GET")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = new Response;

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldFetchTokenFromEnvironment()
    {
        $request = ServerRequestFactory::fromGlobals(
            ["HTTP_BRAWNDO" => "Bearer " . self::$token]
        );
        $request = $request
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET");

        $response = new Response;

        $auth = new JwtAuthentication([
            "environment" => ["HTTP_AUTHORIZATION", "HTTP_BRAWNDO"],
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $this->assertEquals(self::$token, $auth->fetchToken($request));

        $auth = new JwtAuthentication([
            "environment" => "HTTP_BRAWNDO",
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $this->assertEquals(self::$token, $auth->fetchToken($request));
    }

    public function testShouldCallCallback()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = new Response;

        $dummy = null;
        $dummy2 = null;
        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "callback" => function ($request, $response, $arguments) use (&$dummy, &$dummy2) {
                $this->setMessage("Callback was called");
                $dummy = $arguments["decoded"];
                $dummy2 = $arguments["token"];
            }
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
        $this->assertTrue(is_object($dummy));
        $this->assertEquals(self::$token_as_array, (array)$dummy);
        $this->assertEquals(self::$token, $dummy2);
        $this->assertEquals("Callback was called", $auth->getMessage());
    }

    public function testShouldCallError()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET");

        $response = new Response;

        $dummy = null;
        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "error" => function ($request, $response, $arguments) use (&$dummy) {
                $dummy = true;
            }
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
        $this->assertTrue($dummy);
    }

    public function testShouldCallErrorAndModifyBody()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET");

        $response = new Response;

        $dummy = null;
        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "error" => function ($request, $response, $arguments) use (&$dummy) {
                $dummy = true;
                $response->getBody()->write("Error");
                return $response;
            }
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Foo");
            return $response;
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

    public function testShouldGetAndSetPassthrough()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setPassthrough("/admin/ping");
        $this->assertEquals("/admin/ping", $auth->getPassthrough());
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

        $auth->setEnvironment(["HTTP_SOMETHING", "HTTP_OTHER"]);
        $this->assertEquals(["HTTP_SOMETHING", "HTTP_OTHER"], $auth->getEnvironment());
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

    public function testShouldAllowUnauthenticatedHttp()
    {
        $request = (new Request)
            ->withUri(new Uri("http://example.com/public/foo"))
            ->withMethod("GET");

        $response = new Response;

        $auth = new \Slim\Middleware\JwtAuthentication([
            "path" => ["/api", "/bar"],
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) {
            $response->getBody()->write("Success");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldAttachDecodedTokenToRequest()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = new Response;

        $dummy = null;
        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (Request $request, Response $response) use (&$dummy) {
            $dummy = $request->getAttribute("token");
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
        $this->assertTrue(is_object($dummy));
        $this->assertEquals(self::$token_as_array, (array)$dummy);
    }

    public function testShouldGetAndSetAttributeName()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setAttribute("nekot");
        $this->assertEquals("nekot", $auth->getAttribute());
    }

    public function testShouldGetAndSetHeader()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setHeader("X-Token");
        $this->assertEquals("X-Token", $auth->getHeader());
    }

    public function testShouldGetAndSetRegexp()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setRegexp("/Token\s+(.*)$/i");
        $this->assertEquals("/Token\s+(.*)$/i", $auth->getRegexp());
    }

    public function testShouldGetAndSetAlgorithm()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setAlgorithm("HS256");
        $this->assertEquals("HS256", $auth->getAlgorithm());
    }
}
