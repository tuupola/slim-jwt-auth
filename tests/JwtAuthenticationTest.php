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

use \Slim\Middleware\JwtAuthentication\RequestPathRule;

class JwtBasicAuthenticationTest extends \PHPUnit_Framework_TestCase
{
    /* @codingStandardsIgnoreStart */
    public static $token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJBY21lIFRvb3RocGljcyBMdGQiLCJpYXQiOjE0Mjg4MTk5NDEsImV4cCI6MTc0NDM1Mjc0MSwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoic29tZW9uZUBleGFtcGxlLmNvbSIsInNjb3BlIjpbInJlYWQiLCJ3cml0ZSIsImRlbGV0ZSJdfQ.YzPxtyHLqiJMUaPE6DzBonGUyqLlddxIisxSFk2Gk7Y";
    /* @codingStandardsIgnoreEnd */

    public static $token_as_array = array(
        "iss" => "Acme Toothpics Ltd",
        "iat" => "1428819941",
        "exp" => "1744352741",
        "aud" => "www.example.com",
        "sub" => "someone@example.com",
        "scope" => array("read", "write", "delete")
    );

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
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ));

        $auth->setApplication($app);
        $auth->setNextMiddleware($app);
        $auth->call();

        $this->assertEquals(401, $app->response()->status());
        $this->assertEquals("", $app->response()->body());
    }

    public function testShouldReturn200WithToken()
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
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ));

        $auth->setApplication($app);
        $auth->setNextMiddleware($app);
        $auth->call();

        $this->assertEquals(200, $app->response()->status());
        $this->assertEquals("Foo", $app->response()->body());
    }

    public function testShouldReturn401WithFalseFromCallback()
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
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "callback" => function ($decoded, $app) {
                return false;
            }
        ));

        $auth->setApplication($app);
        $auth->setNextMiddleware($app);
        $auth->call();

        $this->assertEquals(401, $app->response()->status());
        $this->assertEquals("", $app->response()->body());
    }

    public function testShouldReturn200WithOptions()
    {
        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/api/foo",
            "REQUEST_METHOD" => "OPTIONS"
        ));
        $app = new \Slim\Slim();
        $app->get("/foo/bar", function () {
            echo "Success";
        });
        $app->options("/api/foo", function () {
            echo "Foo";
        });

        $auth = new \Slim\Middleware\JwtAuthentication(array(
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
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
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ));

        $auth->setApplication($app);
        $auth->setNextMiddleware($app);
        $auth->call();

        $this->assertEquals(400, $app->response()->status());
        $this->assertEquals("", $app->response()->body());
    }

    public function testShouldReturn200WithoutTokenWithPath()
    {
        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/public/foo",
        ));
        $app = new \Slim\Slim();
        $app->get("/public/foo", function () {
            echo "Success";
        });
        $app->get("/api/foo", function () {
            echo "Foo";
        });

        $auth = new \Slim\Middleware\JwtAuthentication(array(
            "path" => "/api",
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
        ));

        $auth->setApplication($app);
        $auth->setNextMiddleware($app);
        $auth->call();

        $this->assertEquals(200, $app->response()->status());
        $this->assertEquals("Success", $app->response()->body());
    }

    public function testShouldFetchTokenFromEnvironment()
    {
        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/public/foo"
        ));

        $_SERVER["HTTP_BRAWNDO"] = "Bearer " . self::$token;

        $auth = new \Slim\Middleware\JwtAuthentication(array(
            "environment" => "HTTP_BRAWNDO",
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ));

        $this->assertEquals(self::$token, $auth->fetchToken());
    }

    public function testShouldCallCallback()
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
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "callback" => function ($decoded, $app) {
                $app->jwt = $decoded;
            }
        ));

        $auth->setApplication($app);
        $auth->setNextMiddleware($app);
        $auth->call();

        $this->assertEquals(200, $app->response()->status());
        $this->assertEquals("Foo", $app->response()->body());
        $this->assertTrue(is_object($app->jwt));
        $this->assertEquals(self::$token_as_array, (array)$app->jwt);
    }

    public function testShouldTestForScope()
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
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
            "callback" => function ($decoded, $app) {
                $app->jwt = $decoded;
            }
        ));

        $auth->setApplication($app);
        $auth->setNextMiddleware($app);
        $auth->call();

        $this->assertEquals(200, $app->response()->status());
        $this->assertEquals("Foo", $app->response()->body());
        $this->assertTrue(is_object($app->jwt));
        $this->assertTrue(in_array("delete", $app->jwt->scope));
    }

    public function testShouldGetAndSetPath()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setPath("/admin");
        $this->assertEquals("/admin", $auth->getPath());
    }

    public function testShouldGetAndSetSecret()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setSecret("supersecretkeyyoushouldnotcommittogithub");
        $this->assertEquals("supersecretkeyyoushouldnotcommittogithub", $auth->getSecret());
    }

    public function testShouldGetAndSetEnvironment()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setEnvironment("HTTP_SOMETHING");
        $this->assertEquals("HTTP_SOMETHING", $auth->getEnvironment());
    }

    public function testShouldGetAndSetCallback()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setCallback(function ($decoded, $app) {
            return true;
        });
        $this->assertTrue(is_callable($auth->getCallback()));
    }

    public function testShouldGetAndSetRules()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setRules([
            function ($app) {
                return true;
            },
            function ($app) {
                return false;
            }
        ]);
        $this->assertEquals(2, count($auth->getRules()));
    }
}
