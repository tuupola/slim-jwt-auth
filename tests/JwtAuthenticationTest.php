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

use Equip\Dispatch\MiddlewareCollection;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Tuupola\Http\Factory\ResponseFactory;
use Tuupola\Http\Factory\ServerRequestFactory;
use Tuupola\Http\Factory\StreamFactory;
use Tuupola\Middleware\JwtAuthentication\RequestMethodRule;
use Tuupola\Middleware\JwtAuthentication\RequestPathRule;

class JwtAuthenticationTest extends \PHPUnit_Framework_TestCase
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
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api");

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromHeader()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("X-Token", "Bearer " . self::$token);

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "header" => "X-Token"
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromHeaderWithCustomRegexp()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("X-Token", self::$token);

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "header" => "X-Token",
            "regexp" => "/(.*)/"
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromCookie()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withCookieParams(["nekot" => self::$token]);

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "cookie" => "nekot",
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn401WithFalseFromAfter()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "after" => function ($request, $response, $arguments) {
                return $response
                    ->withBody((new StreamFactory)->createStream())
                    ->withStatus(401);
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldAlterResponseWithAfter()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "after" => function ($request, $response, $arguments) {
                return $response->withHeader("X-Brawndo", "plants crave");
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("plants crave", (string) $response->getHeaderLine("X-Brawndo"));
    }

    public function testShouldReturn401WithInvalidAlgorithm()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "algorithm" => "nosuch"
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn200WithOptions()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("OPTIONS", "https://example.com/api");

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn400WithInvalidToken()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer invalid" . self::$token);

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn200WithoutTokenWithPath()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/public");

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "path" => ["/api", "/foo"],
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldReturn200WithoutTokenWithIgnore()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api/ping");

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "path" => ["/api", "/foo"],
            "ignore" => ["/api/ping"],
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
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

        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "http://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);
    }

    public function testShoulAllowInsecure()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "http://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "secure" => false
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());

        $response = $auth($request, $response, $next);
    }

    public function testShouldRelaxInsecureInLocalhost()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "http://localhost/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldRelaxInsecureInExampleCom()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "http://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "relaxed" => ["example.com"],
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
    }

    public function testShouldAttachToken()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $token = $request->getAttribute("token");
            $response->getBody()->write($token->iss);
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Acme Toothpics Ltd", $response->getBody());
    }

    public function testShouldAttachCustomToken()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "attribute" => "nekot",
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $token = $request->getAttribute("nekot");
            $response->getBody()->write($token->iss);
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Acme Toothpics Ltd", $response->getBody());
    }

    public function testShouldCallAfter()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = (new ResponseFactory)->createResponse();

        $dummy = null;
        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "after" => function ($request, $response, $arguments) use (&$dummy) {
                $dummy = $arguments["decoded"];
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getBody());
        $this->assertTrue(is_object($dummy));
        $this->assertEquals(self::$token_as_array, (array)$dummy);
    }

    public function testShouldCallError()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api");

        $response = (new ResponseFactory)->createResponse();

        $dummy = null;
        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "error" => function ($request, $response, $arguments) use (&$dummy) {
                $dummy = true;
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
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
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api");

        $response = (new ResponseFactory)->createResponse();

        $dummy = null;
        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "error" => function ($request, $response, $arguments) use (&$dummy) {
                $dummy = true;
                $response->getBody()->write("Error");
                return $response;
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("Error", $response->getBody());
        $this->assertTrue($dummy);
    }

    public function testShouldLog()
    {
        $logger = new \Psr\Log\NullLogger;
        $auth = new \Tuupola\Middleware\JwtAuthentication([
            "logger" => $logger
        ]);
        $this->assertNull($auth->log(\Psr\Log\LogLevel::WARNING, "Token not found"));
    }

    public function testShouldAllowUnauthenticatedHttp()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "http://example.com/public/foo");

        $response = (new ResponseFactory)->createResponse();

        $auth = new \Tuupola\Middleware\JwtAuthentication([
            "path" => ["/api", "/bar"],
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Success");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldReturn401FromAfter()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = (new ResponseFactory)->createResponse();

        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "after" => function ($request, $response, $arguments) {
                return $response
                    ->withBody((new StreamFactory)->createStream())
                    ->withStatus(401);
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Foo");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldModifyRequestUsingBefore()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $response = (new ResponseFactory)->createResponse();

        $dummy = null;
        $auth = new JwtAuthentication([
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "before" => function ($request, $response, $arguments) {
                return $request->withAttribute("test", "test");
            }
        ]);

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $test = $request->getAttribute("test");
            $response->getBody()->write($test);
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("test", (string) $response->getBody());
    }

    public function testShouldHandlePsr15()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api");

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub"
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldHandleRulesArrayBug84()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api");

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "rules" => [
                    new RequestPathRule([
                        "path" => ["/api"],
                        "ignore" => ["/api/login"],
                    ]),
                    new RequestMethodRule([
                        "ignore" => ["OPTIONS"],
                    ])
                ],
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());

        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api/login");

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }
}
