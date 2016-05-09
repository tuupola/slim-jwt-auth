<?php

/*
 * This file is part of Slim JSON Web Token Authentication middleware
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

namespace Test;

use Slim\Middleware\JwtAuthentication\RequestMethodRule;

use Slim\Http\Request;
use Slim\Http\Response;
use Slim\Http\Uri;
use Slim\Http\Headers;
use Slim\Http\Body;
use Slim\Http\Collection;

class RequestMethodTest extends \PHPUnit_Framework_TestCase
{

    public function testShouldNotAuthenticateOptions()
    {
        $uri = Uri::createFromString("https://example.com/api");
        $headers = new Headers();
        $cookies = [];
        $server = [];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("OPTIONS", $uri, $headers, $cookies, $server, $body);

        $rule = new RequestMethodRule();

        $this->assertFalse($rule($request));
    }

    public function testShouldAuthenticatePost()
    {
        $uri = Uri::createFromString("https://example.com/api");
        $headers = new Headers();
        $cookies = [];
        $server = [];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("POST", $uri, $headers, $cookies, $server, $body);

        $rule = new RequestMethodRule();

        $this->assertTrue($rule($request));
    }

    public function testShouldAuthenticateGet()
    {
        $uri = Uri::createFromString("https://example.com/api");
        $headers = new Headers();
        $cookies = [];
        $server = [];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $rule = new RequestMethodRule();

        $this->assertTrue($rule($request));
    }

    public function testShouldConfigurePassThrough()
    {
        $uri = Uri::createFromString("https://example.com/api");
        $headers = new Headers();
        $cookies = [];
        $server = [];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $rule = new RequestMethodRule([
            "passthrough" => ["GET"]
        ]);

        $this->assertFalse($rule($request));
    }
}
