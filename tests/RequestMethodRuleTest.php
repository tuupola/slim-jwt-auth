<?php

/*
 * This file is part of PSR-7 JSON Web Token Authentication middleware
 *
 * Copyright (c) 2015-2018 Mika Tuupola
 *
 * Licensed under the MIT license:
 *   http://www.opensource.org/licenses/mit-license.php
 *
 * Project home:
 *   https://github.com/tuupola/slim-jwt-auth
 *
 */

namespace Slim\Middleware\JwtAuthentication;

use Zend\Diactoros\ServerRequest as Request;
use Zend\Diactoros\ServerRequestFactory;
use Zend\Diactoros\Response;
use Zend\Diactoros\Uri;

class RequestMethodTest extends \PHPUnit_Framework_TestCase
{

    public function testShouldNotAuthenticateOptions()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("OPTIONS");

        $response = new Response;
        $rule = new RequestMethodRule;

        $this->assertFalse($rule($request));
    }

    public function testShouldAuthenticatePost()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("POST");

        $rule = new RequestMethodRule;

        $this->assertTrue($rule($request));
    }

    public function testShouldAuthenticateGet()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET");

        $rule = new RequestMethodRule;

        $this->assertTrue($rule($request));
    }

    public function testShouldConfigurePassThrough()
    {
        $request = (new Request)
            ->withUri(new Uri("https://example.com/api"))
            ->withMethod("GET");

        $rule = new RequestMethodRule([
            "passthrough" => ["GET"]
        ]);

        $this->assertFalse($rule($request));
    }
}
