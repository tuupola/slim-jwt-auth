<?php

/*

Copyright (c) 2015-2021 Mika Tuupola

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

namespace Tuupola\Middleware\JwtAuthentication;

use PHPUnit\Framework\TestCase;
use Tuupola\Http\Factory\ServerRequestFactory;

class RequestPathTest extends TestCase
{
    public function testShouldAcceptArrayAndStringAsPath()
    {
        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/api"
        );

        $rule = new RequestPathRule(["path" => "/api"]);
        $this->assertTrue($rule($request));

        $rule = new RequestPathRule(["path" => ["/api", "/foo"]]);
        $this->assertTrue($rule($request));
    }

    public function testShouldAuthenticateEverything()
    {
        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/"
        );

        $rule = new RequestPathRule(["path" => "/"]);
        $this->assertTrue($rule($request));

        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/api"
        );

        $this->assertTrue($rule($request));
    }

    public function testShouldAuthenticateOnlyApi()
    {
        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/"
        );

        $rule = new RequestPathRule(["path" => "/api"]);
        $this->assertFalse($rule($request));

        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/api"
        );

        $this->assertTrue($rule($request));
    }

    public function testShouldIgnoreLogin()
    {
        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/api"
        );

        $rule = new RequestPathRule([
            "path" => "/api",
            "ignore" => ["/api/login"]
        ]);
        $this->assertTrue($rule($request));

        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/login"
        );

        $this->assertFalse($rule($request));
    }

    public function testShouldAuthenticateCreateAndList()
    {
        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/api"
        );

        /* Should not authenticate */
        $rule = new RequestPathRule(["path" => ["/api/create", "/api/list"]]);
        $this->assertFalse($rule($request));

        /* Should authenticate */
        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/api/create"
        );

        $this->assertTrue($rule($request));

        /* Should authenticate */
        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/api/list"
        );

        $this->assertTrue($rule($request));

        /* Should not authenticate */
        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/api/ping"
        );

        $this->assertFalse($rule($request));
    }

    public function testShouldAuthenticateRegexp()
    {
        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/api/products/123/tickets/anything"
        );

        /* Should authenticate */
        $rule = new RequestPathRule(["path" => ["/api/products/(\d*)/tickets"]]);
        $this->assertTrue($rule($request));

        /* Should not authenticate */
        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/api/products/xxx/tickets"
        );

        $this->assertFalse($rule($request));
    }

    public function testBug50ShouldAuthenticateMultipleSlashes()
    {
        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/"
        );

        $rule = new RequestPathRule(["path" => "/v1/api"]);
        $this->assertFalse($rule($request));

        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/v1/api"
        );

        $this->assertTrue($rule($request));

        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/v1//api"
        );

        $this->assertTrue($rule($request));

        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/v1//////api"
        );

        $this->assertTrue($rule($request));

        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com//v1/api"
        );

        $this->assertTrue($rule($request));

        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com//////v1/api"
        );

        $this->assertTrue($rule($request));
    }
}
