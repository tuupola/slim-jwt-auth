<?php

/*

Copyright (c) 2015-2018 Mika Tuupola

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
use Tuupola\Middleware\JwtAuthentication\RequestMethodRule;
use Tuupola\Middleware\JwtAuthentication\RequestPathRule;

class JwtAuthenticationTest extends TestCase
{
    /* @codingStandardsIgnoreStart */
    public static $token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBY21lIFRvb3RocGljcyBMdGQiLCJpYXQiOjE0Mjg4MTk5NDEsImV4cCI6MTc0NDM1Mjc0MSwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoic29tZW9uZUBleGFtcGxlLmNvbSIsInNjb3BlIjpbInJlYWQiLCJ3cml0ZSIsImRlbGV0ZSJdfQ.YzPxtyHLqiJMUaPE6DzBonGUyqLlddxIisxSFk2Gk7Y";
    public static $expired = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBY21lIFRvb3RocGljcyBMdGQiLCJpYXQiOjE0Mjg4MTk5NDEsImV4cCI6MTQ4MDcyMzIwMCwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoic29tZW9uZUBleGFtcGxlLmNvbSIsInNjb3BlIjpbInJlYWQiLCJ3cml0ZSIsImRlbGV0ZSJdfQ.ZydGEHVmca4ofQRCuMOfZrUXprAoe5GcySg4I-lwIjc";
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

        $default = function (RequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            $auth = new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub"
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromHeader()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("X-Token", "Bearer " . self::$token);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "header" => "X-Token"
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromHeaderWithCustomRegexp()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("X-Token", self::$token);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "header" => "X-Token",
                "regexp" => "/(.*)/"
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldReturn200WithTokenFromCookie()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withCookieParams(["nekot" => self::$token]);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "cookie" => "nekot",
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldAlterResponseWithAfter()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "after" => function ($response, $arguments) {
                    return $response->withHeader("X-Brawndo", "plants crave");
                }
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("plants crave", (string) $response->getHeaderLine("X-Brawndo"));
    }

    public function testShouldReturn401WithInvalidAlgorithm()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "algorithm" => "nosuch",
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldReturn200WithOptions()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withMethod("OPTIONS");

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

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldReturn400WithInvalidToken()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer invalid" . self::$token);

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

    public function testShouldReturn400WithExpiredToken()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$expired);

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

    public function testShouldReturn200WithoutTokenWithPath()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/public");

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "path" => ["/api", "/foo"],
                "secret" => "supersecretkeyyoushouldnotcommittogithub"
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldReturn200WithoutTokenWithIgnore()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api/ping");

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "path" => ["/api", "/foo"],
                "ignore" => ["/api/ping"],
                "secret" => "supersecretkeyyoushouldnotcommittogithub"
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldNotAllowInsecure()
    {
        $this->expectException("RuntimeException");

        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "http://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

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
    }

    public function testShoulAllowInsecure()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "http://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "secure" => false
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldRelaxInsecureInLocalhost()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "http://localhost/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

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

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldRelaxInsecureInExampleCom()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "http://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "relaxed" => ["example.com"],
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldAttachToken()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $default = function (ServerRequestInterface $request) {
            $token = $request->getAttribute("token");

            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write($token["iss"]);

            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub"
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Acme Toothpics Ltd", $response->getBody());
    }

    public function testShouldAttachCustomToken()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $default = function (ServerRequestInterface $request) {
            $token = $request->getAttribute("nekot");

            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write($token["iss"]);

            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "attribute" => "nekot"
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Acme Toothpics Ltd", $response->getBody());
    }

    public function testShouldCallAfter()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $dummy = null;

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "after" => function ($response, $arguments) use (&$dummy) {
                    $dummy = $arguments["decoded"];
                }
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
        $this->assertEquals(self::$token_as_array, (array) $dummy);
    }

    public function testShouldCallError()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api");

        $dummy = null;

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommit",
                "error" => function (
                    ServerRequestInterface $request,
                    ResponseInterface $response,
                    $arguments
                ) use (&$dummy) {
                    $dummy = true;
                }
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
        $this->assertTrue($dummy);
    }

    public function testShouldCallErrorAndModifyBody()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api");

        $dummy = null;

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "error" => function (
                    ServerRequestInterface $request,
                    ResponseInterface $response,
                    $arguments
                ) use (&$dummy) {
                    $dummy = true;
                    $response->getBody()->write("Error");
                    return $response;
                }
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("Error", $response->getBody());
        $this->assertTrue($dummy);
    }

    public function testShouldAllowUnauthenticatedHttp()
    {

        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/public/foo");

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "path" => ["/api", "/bar"],
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }

    public function testShouldReturn401FromAfter()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/api")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $response->getBody()->write("Success");
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "after" => function ($response, $arguments) {
                    return $response
                        ->withBody((new StreamFactory)->createStream())
                        ->withStatus(401);
                }
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals("", $response->getBody());
    }

    public function testShouldModifyRequestUsingBefore()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $test = $request->getAttribute("test");
            $response->getBody()->write($test);
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "before" => function ($request, $arguments) {
                    return $request->withAttribute("test", "test");
                }
            ])
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("test", (string) $response->getBody());
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

    public function testShouldBindToMiddleware()
    {
        $request = (new ServerRequestFactory)
            ->createServerRequest("GET", "https://example.com/")
            ->withHeader("Authorization", "Bearer " . self::$token);

        $default = function (ServerRequestInterface $request) {
            $response = (new ResponseFactory)->createResponse();
            $before = $request->getAttribute("before");
            $response->getBody()->write($before);
            return $response;
        };

        $collection = new MiddlewareCollection([
            new JwtAuthentication([
                "secret" => "supersecretkeyyoushouldnotcommittogithub",
                "before" => function ($request, $arguments) {
                    $before = get_class($this);
                    return $request->withAttribute("before", $before);
                },
                "after" => function ($response, $arguments) {
                    $after = get_class($this);
                    $response->getBody()->write($after);
                    return $response;
                }

            ])
        ]);

        $response = $collection->dispatch($request, $default);
        $expected = str_repeat("Tuupola\Middleware\JwtAuthentication", 2);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals($expected, (string) $response->getBody());
    }

    public function testShouldHandlePsr7()
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
            $response->getBody()->write("Success");
            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals("Success", $response->getBody());
    }
}
