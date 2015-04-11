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

namespace Slim\Middleware\Test;

class JwtBasicAuthenticationTest extends \PHPUnit_Framework_TestCase
{

    /* @codingStandardsIgnoreStart */
    public static $token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBY21lIFRvb3RocGljcyBMdGQiLCJpYXQiOjE0Mjg3NzA3NzEsImV4cCI6MTc0NDMwMzU3MSwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoic29tZW9uZUBleGFtcGxlLmNvbSJ9.o7mAFxGCUWy4v8EOHluAj2ZCSZOpbI_A2CIMvWifBTI";
    /* @codingStandardsIgnoreEnd */

    public function testShouldBeTrue()
    {
        $this->assertTrue(true);
    }

    public function testShouldReturn401WithoutToken()
    {
        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/api/foo",
        ));
        $app = new \Slim\Slim();
        $app->get("/foo/bar", function () {
            echo "Success";
        });
        $app->get("/api/foo", function () {
            echo "Foo";
        });

        $auth = new \Slim\Middleware\JwtAuthentication(array(
            "secret" => "here be dragons"
        ));

        $auth->setApplication($app);
        $auth->setNextMiddleware($app);
        $auth->call();

        $this->assertEquals(401, $app->response()->status());
        $this->assertEquals("", $app->response()->body());
    }

    public function testShouldReturn200WithoutToken()
    {
        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/api/foo",
            "HTTP_AUTHORIZATION" => "Bearer " . self::$token
        ));
        $app = new \Slim\Slim();
        $app->get("/foo/bar", function () {
            echo "Success";
        });
        $app->get("/api/foo", function () {
            echo "Foo";
        });

        $auth = new \Slim\Middleware\JwtAuthentication(array(
            "secret" => "here be dragons"
        ));

        $auth->setApplication($app);
        $auth->setNextMiddleware($app);
        $auth->call();

        $this->assertEquals(200, $app->response()->status());
        $this->assertEquals("Foo", $app->response()->body());
    }

    public function testShouldReturn400WithBrokenToken()
    {
        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/api/foo",
            "HTTP_AUTHORIZATION" => "Bearer broken" . self::$token
        ));
        $app = new \Slim\Slim();
        $app->get("/foo/bar", function () {
            echo "Success";
        });
        $app->get("/api/foo", function () {
            echo "Foo";
        });

        $auth = new \Slim\Middleware\JwtAuthentication(array(
            "secret" => "here be dragons"
        ));

        $auth->setApplication($app);
        $auth->setNextMiddleware($app);
        $auth->call();

        $this->assertEquals(400, $app->response()->status());
        $this->assertEquals("", $app->response()->body());
    }
}
