<?php

declare(strict_types=1);

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
 */

namespace Tuupola\Tests\Middleware;

use Equip\Dispatch\MiddlewareCollection;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Throwable;
use Tuupola\Http\Factory\ResponseFactory;
use Tuupola\Http\Factory\ServerRequestFactory;
use Tuupola\Http\Factory\StreamFactory;
use Tuupola\Middleware\JwtAuthentication;
use Tuupola\Middleware\JwtAuthentication\ArrayAccessSecret;
use Tuupola\Middleware\JwtAuthentication\ArrayOfSecret;
use Tuupola\Middleware\JwtAuthentication\RequestMethodRule;
use Tuupola\Middleware\JwtAuthentication\RequestPathRule;
use Tuupola\Middleware\JwtAuthentication\StringSecret;
use Tuupola\Middleware\JwtAuthenticationOption;
use Tuupola\Middleware\JwtAuthentificationAcl;
use Tuupola\Middleware\JwtAuthentificationAfter;
use Tuupola\Middleware\JwtAuthentificationBefore;
use Tuupola\Middleware\JwtAuthentificationError;
use Tuupola\Middleware\JwtDecodedToken;
use Tuupola\Tests\Middleware\Assets\ArrayAccessImpl;
use Tuupola\Tests\Middleware\Assets\TestAfterHandler;
use Tuupola\Tests\Middleware\Assets\TestBeforeHandler;
use Tuupola\Tests\Middleware\Assets\TestErrorHandler;

use function assert;
use function is_string;
use function json_encode;

class JwtAuthenticationTest extends TestCase
{
    /* @codingStandardsIgnoreStart */
    public static string $acmeToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImFjbWUifQ.eyJpc3MiOiJBY21lIFRvb3RocGljcyBMdGQiLCJpYXQiOiIxNDI4ODE5OTQxIiwiZXhwIjoiMTc0NDM1Mjc0MSIsImF1ZCI6Ind3dy5leGFtcGxlLmNvbSIsInN1YiI6InNvbWVvbmVAZXhhbXBsZS5jb20iLCJzY29wZSI6WyJyZWFkIiwid3JpdGUiLCJkZWxldGUiXX0.yBhYlsMabKTh31taAiH8i2ScPMKm84jxIDNxft6EiTA";
    public static string $betaToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImJldGEifQ.eyJraWQiOiJiZXRhIiwiaXNzIjoiQmV0YSBTcG9uc29yc2hpcCBMdGQiLCJpYXQiOiIxNDI4ODE5OTQxIiwiZXhwIjoiMTc0NDM1Mjc0MSIsImF1ZCI6Ind3dy5leGFtcGxlLmNvbSIsInN1YiI6InNvbWVvbmVAZXhhbXBsZS5jb20iLCJzY29wZSI6WyJyZWFkIl19.msxcBx4_ZQtCkkjHyTDWDC0mac4cFNSxLqkzNL30JB8";
    public static string $expired = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBY21lIFRvb3RocGljcyBMdGQiLCJpYXQiOjE0Mjg4MTk5NDEsImV4cCI6MTQ4MDcyMzIwMCwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoic29tZW9uZUBleGFtcGxlLmNvbSIsInNjb3BlIjpbInJlYWQiLCJ3cml0ZSIsImRlbGV0ZSJdfQ.ZydGEHVmca4ofQRCuMOfZrUXprAoe5GcySg4I-lwIjc";
    /* @codingStandardsIgnoreEnd */

    /** @var array<string, string|string[]> */
    public static array $acmeTokenArray = [
        'iss' => 'Acme Toothpics Ltd',
        'iat' => '1428819941',
        'exp' => '1744352741',
        'aud' => 'www.example.com',
        'sub' => 'someone@example.com',
        'scope' => ['read', 'write', 'delete'],
    ];

    /** @var array<string, string|string[]> */
    public static array $betaTokenArray = [
        'iss' => 'Beta Sponsorship Ltd',
        'iat' => '1428819941',
        'exp' => '1744352741',
        'aud' => 'www.example.com',
        'sub' => 'someone@example.com',
        'scope' => ['read'],
    ];

    public function testShouldReturn401WithoutToken(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api');

        $default = static function (RequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'));

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('', $response->getBody());
    }

    public function testShouldReturn200WithTokenFromHeader(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('X-Token', 'Bearer ' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))->withHeader('X-Token');

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldReturn200WithTokenFromHeaderWithCustomRegexp(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('X-Token', self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withHeader('X-Token')
            ->withRegexp('/(.*)/');

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldReturn200WithTokenFromCookie(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withCookieParams(['nekot' => self::$acmeToken]);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withCookie('nekot');

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldReturn200WithTokenFromBearerCookie(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withCookieParams(['nekot' => 'Bearer ' . self::$acmeToken]);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withCookie('nekot');

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldReturn200WithSecretArray(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$betaToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new ArrayOfSecret([
            'acme' => 'supersecretkeyyoushouldnotcommittogithub',
            'beta' => 'anothersecretkeyfornevertocommittogithub',
        ]));

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldReturn401WithSecretArray(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$betaToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new ArrayOfSecret([
            'xxxx' => 'supersecretkeyyoushouldnotcommittogithub',
            'yyyy' => 'anothersecretkeyfornevertocommittogithub',
        ]));

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('', $response->getBody());
    }

    public function testShouldReturn200WithSecretArrayAccess(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$betaToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $secret         = new ArrayAccessImpl();
        $secret['acme'] = 'supersecretkeyyoushouldnotcommittogithub';
        $secret['beta'] = 'anothersecretkeyfornevertocommittogithub';

        $option = JwtAuthenticationOption::create(new ArrayAccessSecret($secret));

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldReturn401WithSecretArrayAccess(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$betaToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $secret         = new ArrayAccessImpl();
        $secret['xxxx'] = 'supersecretkeyyoushouldnotcommittogithub';
        $secret['yyyy'] = 'anothersecretkeyfornevertocommittogithub';

        $option = JwtAuthenticationOption::create(new ArrayAccessSecret($secret));

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);
        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('', $response->getBody());
    }

    public function testShouldAlterResponseWithAnonymousAfter(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withAfter(new class implements JwtAuthentificationAfter {
                public function __invoke(ResponseInterface $response, JwtDecodedToken $jwtDecodedToken): ResponseInterface
                {
                    return $response->withHeader('X-Brawndo', 'plants crave');
                }
            });

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('plants crave', (string) $response->getHeaderLine('X-Brawndo'));
    }

    public function testShouldAlterResponseWithInvokableAfter(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withAfter(new TestAfterHandler());

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals(
            'plants crave',
            (string) $response->getHeaderLine('X-Brawndo'),
        );
    }

    public function testShouldReturn401WithInvalidAlgorithm(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withAlgorithm('nosuch');

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('', $response->getBody());
    }

    public function testShouldReturn200WithOptions(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withMethod('OPTIONS');

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'));

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldReturn400WithInvalidToken(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('Authorization', 'Bearer invalid' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'));

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('', $response->getBody());
    }

    public function testShouldReturn400WithExpiredToken(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$expired);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'));

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('', $response->getBody());
    }

    public function testShouldReturn200WithoutTokenWithPath(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/public');

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withPath(['/api', '/foo'])
            ->addRule(new RequestPathRule(['/api', '/foo'], []));

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldReturn200WithoutTokenWithIgnore(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api/ping');

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withPath(['/api', '/foo'])
            ->withIgnore(['/api/ping'])
            ->addRule(new RequestPathRule(['/api', '/foo'], ['/api/ping']));

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldNotAllowInsecure(): void
    {
        $this->expectException('RuntimeException');

        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'http://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'));

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);
    }

    public function testShouldAllowInsecure(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'http://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withSecure(false);

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldRelaxInsecureInLocalhost(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'http://localhost/api')
            ->withHeader('Authorization', 'Bearer ' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'));

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldRelaxInsecureInExampleCom(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'http://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withRelaxed(['example.com']);

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldAttachToken(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $decodedToken = $request->getAttribute('token');

            assert($decodedToken instanceof JwtDecodedToken);

            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write($decodedToken->getStringAttribute('iss'));

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'));

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Acme Toothpics Ltd', $response->getBody());
    }

    public function testShouldAttachCustomToken(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $decodedToken = $request->getAttribute('nekot');

            assert($decodedToken instanceof JwtDecodedToken);

            $acmeToken = $decodedToken->payload;

            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write($decodedToken->getStringAttribute('iss'));

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withAttribute('nekot');

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Acme Toothpics Ltd', $response->getBody());
    }

    public function testShouldCallAfterWithProperArguments(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withAfter(new class implements JwtAuthentificationAfter {
                public function __invoke(ResponseInterface $response, JwtDecodedToken $jwtDecodedToken): ResponseInterface
                {
                    return $response->withHeader('decoded', (string) json_encode($jwtDecodedToken->payload))->withHeader('token', $jwtDecodedToken->token);
                }
            });

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
        $this->assertJsonStringEqualsJsonString((string) json_encode(self::$acmeTokenArray), $response->getHeaderLine('decoded'));
        $this->assertEquals(self::$acmeToken, $response->getHeaderLine('token'));
    }

    public function testShouldCallBeforeWithProperArguments(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$acmeToken);

        $decoded = null;
        $token   = null;

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success' . $request->getAttribute('decoded') . $request->getAttribute('token'));

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withBefore(new class implements JwtAuthentificationBefore {
                public function __invoke(ServerRequestInterface $request, JwtDecodedToken $jwtDecodedToken): ServerRequestInterface
                {
                    return $request->withAttribute('decoded', json_encode($jwtDecodedToken->payload))
                        ->withAttribute('token', $jwtDecodedToken->token);
                }
            });

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success' . json_encode(self::$acmeTokenArray) . self::$acmeToken, $response->getBody());
    }

    public function testShouldCallAnonymousErrorFunction(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api');

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withError(new class implements JwtAuthentificationError {
                public function __invoke(ServerRequestInterface $request, ResponseInterface $response, Throwable $exception): ResponseInterface
                {
                    $response->getBody()->write('error');

                    return $response
                        ->withHeader('X-Electrolytes', 'Plants');
                }
            });

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('Plants', $response->getHeaderLine('X-Electrolytes'));
        $this->assertEquals('error', $response->getBody());
    }

    public function testShouldCallInvokableErrorClass(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api');

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withError(new TestErrorHandler());

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(402, $response->getStatusCode());
        $this->assertEquals('Bar', $response->getHeaderLine('X-Foo'));
        $this->assertEquals(TestErrorHandler::class, $response->getBody());
    }

    public function testShouldCallErrorAndModifyBody(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api');

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withError(new class implements JwtAuthentificationError {
                public function __invoke(ServerRequestInterface $request, ResponseInterface $response, Throwable $exception): ResponseInterface
                {
                     $response->getBody()->write('Error');

                    return $response;
                }
            });

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('Error', $response->getBody());
    }

    public function testShouldAllowUnauthenticatedHttp(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/public/foo');

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withPath(['/api', '/bar'])
            ->addRule(new RequestPathRule(['/api', '/foo'], []));

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);
        $response   = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldReturn401FromAfter(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('Authorization', 'Bearer ' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withAfter(new class implements JwtAuthentificationAfter {
                public function __invoke(ResponseInterface $response, JwtDecodedToken $jwtDecodedToken): ResponseInterface
                {
                    return $response
                        ->withBody((new StreamFactory())->createStream())
                        ->withStatus(401);
                }
            });

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('', $response->getBody());
    }

    public function testShouldModifyRequestUsingAnonymousBefore(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/')
            ->withHeader('Authorization', 'Bearer ' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $test     = $request->getAttribute('test');
            $response->getBody()->write(is_string($test) ? $test : 'no');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withBefore(new class implements JwtAuthentificationBefore {
                public function __invoke(ServerRequestInterface $request, JwtDecodedToken $jwtDecodedToken): ServerRequestInterface
                {
                    return $request->withAttribute('test', 'test');
                }
            });

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('test', (string) $response->getBody());
    }

    public function testShouldModifyRequestUsingInvokableBefore(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/')
            ->withHeader('Authorization', 'Bearer ' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $test     = $request->getAttribute('test');
            $response->getBody()->write(is_string($test) ? $test : 'no');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withBefore(new TestBeforeHandler());

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('invoke', (string) $response->getBody());
    }

    public function testShouldHandleRulesArrayBug84(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api');

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withRules(
                new RequestPathRule(['/api'], ['/api/login']),
                new RequestMethodRule(['OPTIONS']),
            );

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('', $response->getBody());

        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api/login');

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldHandleDefaultPathBug118(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api');

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withIgnore(['/api/login'])
            ->addRule(new RequestPathRule(['/'], ['/api/login']));

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('', $response->getBody());

        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api/login');

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldBindToMiddleware(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/')
            ->withHeader('Authorization', 'Bearer ' . self::$acmeToken);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $before   = $request->getAttribute('before');
            $response->getBody()->write(is_string($before) ? $before : 'no');

            return $response;
        };

        $option =                 JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withAfter(new class implements JwtAuthentificationAfter {
                public function __invoke(ResponseInterface $response, JwtDecodedToken $jwtDecodedToken): ResponseInterface
                {
                     $response->getBody()->write('im after');

                    return $response;
                }
            })
            ->withBefore(new class implements JwtAuthentificationBefore {
                public function __invoke(ServerRequestInterface $request, JwtDecodedToken $jwtDecodedToke): ServerRequestInterface
                {
                    return $request->withAttribute('before', 'im before');
                }
            });

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('im beforeim after', (string) $response->getBody());
    }

    public function testShouldHandlePsr7(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withHeader('X-Token', 'Bearer ' . self::$acmeToken);

        $response = (new ResponseFactory())->createResponse();

        $option =                 JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withHeader('X-Token');

        $auth = new JwtAuthentication($option);

        $next = static function (ServerRequestInterface $request, ResponseInterface $response) {
            $response->getBody()->write('Success');

            return $response;
        };

        $response = $auth($request, $response, $next);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }

    public function testShouldHaveUriInErrorHandlerIssue96(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api/foo?bar=pop');

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option =                 JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withError(new class implements JwtAuthentificationError {
                public function __invoke(ServerRequestInterface $request, ResponseInterface $response, Throwable $exception): ResponseInterface
                {
                    return $response->withHeader('X-Uri', (string) $request->getUri());
                }
            });

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(401, $response->getStatusCode());
        $this->assertEquals('', $response->getBody());
        $this->assertEquals('https://example.com/api/foo?bar=pop', $response->getHeaderLine('X-Uri'));
    }

    public function testShouldUseCookieIfHeaderMissingIssue156(): void
    {
        $request = (new ServerRequestFactory())
            ->createServerRequest('GET', 'https://example.com/api')
            ->withCookieParams(['token' => self::$acmeToken]);

        $default = static function (ServerRequestInterface $request) {
            $response = (new ResponseFactory())->createResponse();
            $response->getBody()->write('Success');

            return $response;
        };

        $option = JwtAuthenticationOption::create(new StringSecret('supersecretkeyyoushouldnotcommittogithub'))
            ->withHeader('X-Token')
            ->withRegexp('/(.*)/');

        $collection = new MiddlewareCollection([
            new JwtAuthentication($option),
            new JwtAuthentificationAcl($option),
        ]);

        $response = $collection->dispatch($request, $default);

        $this->assertEquals(200, $response->getStatusCode());
        $this->assertEquals('Success', $response->getBody());
    }
}
