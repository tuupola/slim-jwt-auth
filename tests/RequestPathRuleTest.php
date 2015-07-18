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


namespace Test;

use Slim\Middleware\JwtAuthentication\RequestPathRule;

use Slim\Http\Request;
use Slim\Http\Response;
use Slim\Http\Uri;
use Slim\Http\Headers;
use Slim\Http\Body;
use Slim\Http\Collection;

class RequestPathTest extends \PHPUnit_Framework_TestCase
{
    public function testShouldAcceptArrayAndStringAsPath()
    {
        $uri = Uri::createFromString("https://example.com/api");
        $headers = new Headers();
        $cookies = [];
        $server = [];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $rule = new RequestPathRule(["path" => "/api"]);
        $this->assertTrue($rule($request));

        $this->assertTrue($rule($request));

        $rule = new RequestPathRule(["path" => ["/api", "/foo"]]);
        $this->assertTrue($rule($request));
    }

    public function testShouldAuthenticateEverything()
    {
        $uri = Uri::createFromString("https://example.com/");
        $headers = new Headers();
        $cookies = [];
        $server = [];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $rule = new RequestPathRule(["path" => "/"]);
        $this->assertTrue($rule($request));

        $uri = Uri::createFromString("https://example.com/api");
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $this->assertTrue($rule($request));
    }

    public function testShouldAuthenticateOnlyApi()
    {
        $uri = Uri::createFromString("https://example.com/");
        $headers = new Headers();
        $cookies = [];
        $server = [];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $rule = new RequestPathRule(["path" => "/api"]);
        $this->assertFalse($rule($request));

        $uri = Uri::createFromString("https://example.com/api");
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $this->assertTrue($rule($request));
    }

    public function testShouldPassthroughLogin()
    {
        $uri = Uri::createFromString("https://example.com/api");
        $headers = new Headers();
        $cookies = [];
        $server = [];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $rule = new RequestPathRule([
            "path" => "/api",
            "passthrough" => ["/api/login"]
        ]);
        $this->assertTrue($rule($request));

        $uri = Uri::createFromString("https://example.com/api/login");
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        $this->assertFalse($rule($request));
    }

    public function testShouldAuthenticateCreateAndList()
    {
        $uri = Uri::createFromString("https://example.com/api");
        $headers = new Headers();
        $cookies = [];
        $server = [];
        $body = new Body(fopen("php://temp", "r+"));
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);

        /* Should not authenticate */
        $rule = new RequestPathRule(["path" => ["/api/create", "/api/list"]]);
        $this->assertFalse($rule($request));

        /* Should authenticate */
        $uri = Uri::createFromString("https://example.com/api/create");
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);
        $this->assertTrue($rule($request));

        /* Should authenticate */
        $uri = Uri::createFromString("https://example.com/api/list");
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);
        $this->assertTrue($rule($request));

        /* Should not authenticate */
        $uri = Uri::createFromString("https://example.com/api/ping");
        $request = new Request("GET", $uri, $headers, $cookies, $server, $body);
        $this->assertFalse($rule($request));
    }
}
