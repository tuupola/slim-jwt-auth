<?php

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

use Equip\Dispatch\MiddlewareCollection;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Tuupola\Http\Factory\ResponseFactory;
use Tuupola\Http\Factory\ServerRequestFactory;
use Tuupola\Http\Factory\StreamFactory;
use Tuupola\Middleware\JwtAuthentication\JwtAuthOptions;
use Tuupola\Middleware\JwtAuthentication\RequestMethodRule;
use Tuupola\Middleware\JwtAuthentication\RequestPathRule;

class JwtAuthenticationTest extends TestCase
{
    /* @codingStandardsIgnoreStart */
    public static $acmeToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImFjbWUifQ.eyJpc3MiOiJBY21lIFRvb3RocGljcyBMdGQiLCJpYXQiOiIxNDI4ODE5OTQxIiwiZXhwIjoiMTc0NDM1Mjc0MSIsImF1ZCI6Ind3dy5leGFtcGxlLmNvbSIsInN1YiI6InNvbWVvbmVAZXhhbXBsZS5jb20iLCJzY29wZSI6WyJyZWFkIiwid3JpdGUiLCJkZWxldGUiXX0.yBhYlsMabKTh31taAiH8i2ScPMKm84jxIDNxft6EiTA";
    public static $betaToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImJldGEifQ.eyJraWQiOiJiZXRhIiwiaXNzIjoiQmV0YSBTcG9uc29yc2hpcCBMdGQiLCJpYXQiOiIxNDI4ODE5OTQxIiwiZXhwIjoiMTc0NDM1Mjc0MSIsImF1ZCI6Ind3dy5leGFtcGxlLmNvbSIsInN1YiI6InNvbWVvbmVAZXhhbXBsZS5jb20iLCJzY29wZSI6WyJyZWFkIl19.msxcBx4_ZQtCkkjHyTDWDC0mac4cFNSxLqkzNL30JB8";
    public static $expired = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBY21lIFRvb3RocGljcyBMdGQiLCJpYXQiOjE0Mjg4MTk5NDEsImV4cCI6MTQ4MDcyMzIwMCwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoic29tZW9uZUBleGFtcGxlLmNvbSIsInNjb3BlIjpbInJlYWQiLCJ3cml0ZSIsImRlbGV0ZSJdfQ.ZydGEHVmca4ofQRCuMOfZrUXprAoe5GcySg4I-lwIjc";
    /* @codingStandardsIgnoreEnd */

    public static $acmeTokenArray = [
        "iss" => "Acme Toothpics Ltd",
        "iat" => "1428819941",
        "exp" => "1744352741",
        "aud" => "www.example.com",
        "sub" => "someone@example.com",
        "scope" => ["read", "write", "delete"],
    ];

    public static $betaTokenArray = [
        "iss" => "Beta Sponsorship Ltd",
        "iat" => "1428819941",
        "exp" => "1744352741",
        "aud" => "www.example.com",
        "sub" => "someone@example.com",
        "scope" => ["read"],
    ];

    public function testShouldReturn401WithoutToken()
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            "GET",
            "https://example.com/api"
        );

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();

            $response->getBody()->write("Success");
            return $response;
        };
        $options = new JwtAuthOptions(
            "supersecretkeyyoushouldnotcommittogithub"
        );
        $collection = new MiddlewareCollection([
            new JwtAuthentication($options),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromHeader()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("X-Token", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $options = JwtAuthOptions::fromArray(
            [
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "header" => "X-Token",
            ]
        );

        $collection = new MiddlewareCollection([
            new JwtAuthentication($options),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromHeaderWithCustomRegexp()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("X-Token", self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $options = JwtAuthOptions::fromArray(
            [
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "header" => "X-Token",
                "regexp" => "/(.*)/",
            ]
        );

        $collection = new MiddlewareCollection([
            new JwtAuthentication($options),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromCookie()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withCookieParams(["nekot" => self::$acmeToken]);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $options = JwtAuthOptions::fromArray(
            [
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "cookie" => "nekot",
            ]
        );

        $collection = new MiddlewareCollection([
            new JwtAuthentication($options),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromBearerCookie()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withCookieParams(["nekot" => "Bearer " . self::$acmeToken]);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $options = JwtAuthOptions::fromArray(
            [
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "cookie" => "nekot",
            ]
        );

        $collection = new MiddlewareCollection([
            new JwtAuthentication($options),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldReturn200WithSecretArray()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$betaToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $options = JwtAuthOptions::fromArray(
            [
                "secret" => [
                    "acme" => "supersecretkeyyoushouldnotcommittogithub",
                    "beta" => "anothersecretkeyfornevertocommittogithub"
                ]
            ]
        );

        $collection = new MiddlewareCollection([
            new JwtAuthentication($options)
        ]);

        $response = $collection->dispatch($request, $default);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldReturn401WithSecretArray()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$betaToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => [
                            "xxxx" => "supersecretkeyyoushouldnotcommittogithub",
                            "yyyy" => "anothersecretkeyfornevertocommittogithub"
                        ]
                    ]
                )
            )
        ]);

        $response = $collection->dispatch($request, $default);
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn200WithSecretArrayAccess()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$betaToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $secret = new \ArrayObject();
        $secret["acme"] = "supersecretkeyyoushouldnotcommittogithub";
        $secret["beta"] = "anothersecretkeyfornevertocommittogithub";

        $options = JwtAuthOptions::fromArray([
            "secret" => $secret
        ]);

        $collection = new MiddlewareCollection([
            new JwtAuthentication($options)
        ]);

        $response = $collection->dispatch($request, $default);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldReturn401WithSecretArrayAccess()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$betaToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $secret = new \ArrayObject();
        $secret["xxxx"] = "supersecretkeyyoushouldnotcommittogithub";
        $secret["yyyy"] = "anothersecretkeyfornevertocommittogithub";

        $options = JwtAuthOptions::fromArray([
            "secret" => $secret
        ]);

        $collection = new MiddlewareCollection([
            new JwtAuthentication($options)
        ]);

        $response = $collection->dispatch($request, $default);
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldAlterResponseWithAnonymousAfter()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "after" => function ($response, $arguments) {
                            return $response->withHeader(
                                "X-Brawndo",
                                "plants crave"
                            );
                        },
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(
            "plants crave",
            (string) $response->getHeaderLine("X-Brawndo")
        );
    }

    public function testShouldAlterResponseWithInvokableAfter()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "after" => new TestAfterHandler(),
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(
            "plants crave",
            (string) $response->getHeaderLine("X-Brawndo")
        );
    }

    public function testShouldAlterResponseWithArrayNotationAfter()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "after" => [TestAfterHandler::class, "after"],
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(
            "like from toilet?",
            (string) $response->getHeaderLine("X-Water")
        );
    }

    public function testShouldReturn401WithInvalidAlgorithm()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "algorithm" => "nosuch",
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn200WithOptions()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withMethod("OPTIONS");

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldReturn400WithInvalidToken()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer invalid" . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn400WithExpiredToken()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$expired);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn200WithoutTokenWithPath()
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            "GET",
            "https://example.com/public"
        );

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "path" => ["/api", "/foo"],
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody()->__toString());
    }

    public function testShouldReturn200WithoutTokenWithIgnore()
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            "GET",
            "https://example.com/api/ping"
        );

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "path" => ["/api", "/foo"],
                        "ignore" => ["/api/ping"],
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldNotAllowInsecure()
    {
        $this->expectException("RuntimeException");

        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "http://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);
    }

    public function testShouldAllowInsecure()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "http://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "secure" => false,
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldRelaxInsecureInLocalhost()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "http://localhost/api")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldRelaxInsecureInExampleCom()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "http://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "relaxed" => ["example.com"],
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldAttachToken()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $acmeToken = $request->getAttribute("token");

            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write($acmeToken["iss"]);

            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Acme Toothpics Ltd", $response->getBody());
    }

    public function testShouldAttachCustomToken()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $acmeToken = $request->getAttribute("nekot");

            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write($acmeToken["iss"]);

            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "attribute" => "nekot",
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Acme Toothpics Ltd", $response->getBody());
    }

    public function testShouldCallAfterWithProperArguments()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $decoded = null;
        $token = null;

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "after" => function ($response, $arguments) use (&$decoded, &$token) {
                            $decoded = $arguments["decoded"];
                            $token = $arguments["token"];
                        },
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
        $this->assertEquals(self::$acmeTokenArray, (array) $decoded);
        $this->assertEquals(self::$acmeToken, $token);
    }

    public function testShouldCallBeforeWithProperArguments()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $decoded = null;
        $token = null;

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "before" => function ($response, $arguments) use (&$decoded, &$token) {
                            $decoded = $arguments["decoded"];
                            $token = $arguments["token"];
                        },
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
        $this->assertEquals(self::$acmeTokenArray, (array) $decoded);
        $this->assertEquals(self::$acmeToken, $token);
    }

    public function testShouldCallAnonymousErrorFunction()
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            "GET",
            "https://example.com/api"
        );

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommit",
                        "error" => function (ResponseInterface $response, $arguments) use (&$dummy) {
                            $response->getBody()->write("error");
                            return $response->withHeader(
                                "X-Electrolytes",
                                "Plants"
                            );
                        },
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals(
            "Plants",
            $response->getHeaderLine("X-Electrolytes")
        );
        $this->assertEquals("error", $response->getBody());
    }

    public function testShouldCallInvokableErrorClass()
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            "GET",
            "https://example.com/api"
        );

        $dummy = null;

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommit",
                        "error" => new TestErrorHandler(),
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(402, $response->getStatusCode());
        $this->assertEquals("Bar", $response->getHeaderLine("X-Foo"));
        $this->assertEquals(TestErrorHandler::class, $response->getBody());
    }

    public function testShouldCallArrayNotationError()
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            "GET",
            "https://example.com/api"
        );

        $dummy = null;

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommit",
                        "error" => [TestErrorHandler::class, "error"],
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(418, $response->getStatusCode());
        $this->assertEquals("Foo", $response->getHeaderLine("X-Bar"));
        $this->assertEquals(TestErrorHandler::class, $response->getBody());
    }

    public function testShouldCallErrorAndModifyBody()
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            "GET",
            "https://example.com/api"
        );

        $dummy = null;

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "error" => function (ResponseInterface $response, $arguments) use (&$dummy) {
                            $dummy = true;
                            $response->getBody()->write("Error");
                            return $response;
                        },
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("Error", $response->getBody());
        $this->assertTrue($dummy);
    }

    public function testShouldAllowUnauthenticatedHttp()
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            "GET",
            "https://example.com/public/foo"
        );

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "path" => ["/api", "/bar"],
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldReturn401FromAfter()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "after" => function ($response, $arguments) {
                            return $response
                                ->withBody(
                                    (new StreamFactory())->createStream()
                                )
                                ->withStatus(401);
                        },
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldModifyRequestUsingAnonymousBefore()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $test = $request->getAttribute("test");
            $response->getBody()->write($test);
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "before" => function ($request, $arguments) {
                            return $request->withAttribute("test", "test");
                        },
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("test", (string) $response->getBody());
    }

    public function testShouldModifyRequestUsingInvokableBefore()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $test = $request->getAttribute("test");
            $response->getBody()->write($test);
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "before" => new TestBeforeHandler(),
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("invoke", (string) $response->getBody());
    }

    public function testShouldModifyRequestUsingArrayNotationBefore()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $test = $request->getAttribute("test");
            $response->getBody()->write($test);
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "before" => [TestBeforeHandler::class, "before"],
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("function", (string) $response->getBody());
    }

    public function testShouldHandleRulesArrayBug84()
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            "GET",
            "https://example.com/api"
        );

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "rules" => [
                            new RequestPathRule([
                                "path" => ["/api"],
                                "ignore" => ["/api/login"],
                            ]),
                            new RequestMethodRule([
                                "ignore" => ["OPTIONS"],
                            ]),
                        ],
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());

        $request = (new ServerRequestFactory())->createServerRequest(
            "GET",
            "https://example.com/api/login"
        );

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldHandleDefaultPathBug118()
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            "GET",
            "https://example.com/api"
        );

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "ignore" => ["/api/login"],
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());

        $request = (new ServerRequestFactory())->createServerRequest(
            "GET",
            "https://example.com/api/login"
        );

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldBindToMiddleware()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/")
            ->withHeader("Authorization", "Bearer " . self::$acmeToken);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $before = $request->getAttribute("before");
            $response->getBody()->write($before);
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "before" => function (ServerRequestInterface $request, $arguments) {
                            $before = get_class($this);
                            var_dump($before);
                            return $request->withAttribute("before", $before);
                        },
                        "after" => function ($response, $arguments) {
                            $after = get_class($this);
                            $response->getBody()->write($after);
                            return $response;
                        },
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);
        $expected = str_repeat("Tuupola\Middleware\JwtAuthentication", 2);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals($expected, (string) $response->getBody());
    }

    public function testShouldHandlePsr7()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("X-Token", "Bearer " . self::$acmeToken);

        $response = (new ResponseFactory())->createResponse();

        $auth = new JwtAuthentication(
            JwtAuthOptions::fromArray(
                [
                    "secret" => "supersecretkeyyoushouldnotcommittogithub",
                    "header" => "X-Token",
                ]
            )
        );

        $next = function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write("Success");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldHaveUriInErrorHandlerIssue96()
    {
        $request = (new ServerRequestFactory())->createServerRequest(
            "GET",
            "https://example.com/api/foo?bar=pop"
        );

        $dummy = null;

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "error" => function (ResponseInterface $response, $arguments) use (&$dummy) {
                            $dummy = $arguments["uri"];
                        },
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
        $this->assertEquals("https://example.com/api/foo?bar=pop", $dummy);
    }

    public function testShouldUseCookieIfHeaderMissingIssue156()
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest("GET", "https://example.com/api")
            ->withCookieParams(["token" => self::$acmeToken]);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication(
                JwtAuthOptions::fromArray(
                    [
                        "secret" => "supersecretkeyyoushouldnotcommittogithub",
                        "header" => "X-Token",
                        "regexp" => "/(.*)/",
                    ]
                )
            ),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }
}
