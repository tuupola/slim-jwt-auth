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

namespace Tuupola\Middleware\JwtAuthentication;

use PHPUnit\Framework\TestCase;
use Tuupola\Http\Factory\ServerRequestFactory;

class RequestMethodTest extends TestCase
{

    public function testShouldNotAuthenticateOptions()
    {
        $request = (new ServerRequestFactory)->createServerRequest(
            "OPTIONS",
            "https://example.com/api"
        );

        $rule = new RequestMethodRule;

        $this->assertFalse($rule($request));
    }

    public function testShouldAuthenticatePost()
    {
        $request = (new ServerRequestFactory)->createServerRequest(
            "POST",
            "https://example.com/api"
        );

        $rule = new RequestMethodRule;

        $this->assertTrue($rule($request));
    }

    public function testShouldAuthenticateGet()
    {
        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/api"
        );

        $rule = new RequestMethodRule;

        $this->assertTrue($rule($request));
    }

    public function testShouldConfigureIgnore()
    {
        $request = (new ServerRequestFactory)->createServerRequest(
            "GET",
            "https://example.com/api"
        );

        $rule = new RequestMethodRule([
            "ignore" => ["GET"]
        ]);

        $this->assertFalse($rule($request));
    }
}
