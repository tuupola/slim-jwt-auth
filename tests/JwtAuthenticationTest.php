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
    public static $encrypted_token = "1759312687%7CidjRp0QQZL5WDQHfXsMKw%2F%2B3apXiwNkIdR1on6ysAnEzeHmPNemh5uAGnk0DoXOYymvr%2FRpr8spBbaS2oO0Cvs%2BTqA2nuxGauRFA9%2FVUD%2BVX8Wj5d5YzzDCuaDs0RlHT0%2F9avFHBVMrOGgnso2Hyo6oVNB%2BrqSrH4QT8PzFHDZbhKuXQ2h5Dr5ADpYmKYvSqidH0%2FooP1lh2uuej2aUoaNf7KT2TEjm36ahy7svhnJL0G%2B2dgrXeoJN%2BHxtfdLU8lkc4iJmVvls%2B7ruu%2BRkMtE8dkRI2P7uCOAV7Eoz1Nym8ipIwnP2C5Z9wVdvj%2FRGa%2Bf7PVWmqJNsoyqgBTcqrTLbiKa4twe5HFzfiY4svg933dLgRzyXFzx4aAx0s%2B0Js%7Cf3adb3d4093ebcab9f8b16759ebfc0800f6ddf9f";
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
            "slim.url_scheme" => "https"
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

    public function testShouldReturn200WithTokenFromEnvironment()
    {
        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/api/foo",
            "HTTP_AUTHORIZATION" => "Bearer " . self::$token,
            "slim.url_scheme" => "https"
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

    public function testShouldReturn200WithTokenFromCookie()
    {
        \Slim\Environment::mock(array(
            "HTTP_COOKIE" => "token=" . self::$token,
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/api/foo",
            "slim.url_scheme" => "https"
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

    public function testShouldReturn200WithTokenFromEncryptedCookie()
    {
        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/api/foo",
            "HTTP_COOKIE" => "token=" . self::$encrypted_token,
            "slim.url_scheme" => "https"
        ));

        $app = new \Slim\Slim(array(
            "cookies.encrypt" => true,
            "cookies.secret_key" => "cookiekey",
            "cookies.cipher" => MCRYPT_RIJNDAEL_256,
            "cookies.cipher_mode" => MCRYPT_MODE_CBC
        ));

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
            "HTTP_AUTHORIZATION" => "Bearer " . self::$token,
            "slim.url_scheme" => "https"
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
            "callback" => function ($params) {
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
            "REQUEST_METHOD" => "OPTIONS",
            "slim.url_scheme" => "https"
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

    public function testShouldReturn401WithInvalidToken()
    {
        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/api/foo",
            "HTTP_AUTHORIZATION" => "Bearer invalid" . self::$token,
            "slim.url_scheme" => "https"
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

    public function testShouldReturn200WithoutTokenWithPath()
    {
        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/public/foo",
            "slim.url_scheme" => "https"
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

    public function testShouldReturn200WithoutTokenWithPassthrough()
    {

        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/api/ping",
            "slim.url_scheme" => "https"
        ));
        $app = new \Slim\Slim();
        $app->get("/public/foo", function () {
            echo "Success";
        });
        $app->get("/api/ping", function () {
            echo "Pong";
        });

        $auth = new \Slim\Middleware\JwtAuthentication(array(
            "path" => "/api",
            "passthrough" => ["/api/ping"],
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
        ));

        $auth->setApplication($app);
        $auth->setNextMiddleware($app);
        $auth->call();

        $this->assertEquals(200, $app->response()->status());
        $this->assertEquals("Pong", $app->response()->body());

    }

    public function testShouldNotAllowInsecure()
    {

        $this->setExpectedException("RuntimeException");

        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/api/foo",
            "SERVER_NAME" => "dev.example.com",
            "slim.url_scheme" => "http"
        ));

        $app = new \Slim\Slim();
        $app->get("/public/foo", function () {
            echo "Success";
        });
        $app->get("/api/foo", function () {
            echo "Foo";
        });

        $auth = new \Slim\Middleware\JwtAuthentication(array(
            "path" => array("/api"),
            "secret" => "supersecretkeyyoushouldnotcommittogithub",
        ));

        $auth->setApplication($app);
        $auth->setNextMiddleware($app);
        $auth->call();
    }

    public function testShouldRelaxInsecureInLocalhost()
    {
        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/public/foo",
            "SERVER_NAME" => "localhost",
            "slim.url_scheme" => "http"
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
            "PATH_INFO" => "/public/foo",
            "slim.url_scheme" => "https"
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
            "HTTP_AUTHORIZATION" => "Bearer " . self::$token,
            "slim.url_scheme" => "https"
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
            "callback" => function ($params) {
                $params["app"]->jwt = $params["decoded"];
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
            "HTTP_AUTHORIZATION" => "Bearer " . self::$token,
            "slim.url_scheme" => "https"
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
            "callback" => function ($params) {
                $params["app"]->jwt = $params["decoded"];
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
        $auth->setPassthrough("/admin/ping");
        $this->assertEquals("/admin/ping", $auth->getPassthrough());
    }

    public function testShouldGetAndSetPassthrough()
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

    public function testShouldGetAndSetSecure()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $this->assertTrue($auth->getSecure());
        $auth->setSecure(false);
        $this->assertFalse($auth->getSecure());
    }

    public function testShouldGetAndSetRelaxed()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $relaxed = array("localhost", "dev.example.com");
        $auth->setRelaxed($relaxed);
        $this->assertEquals($relaxed, $auth->getRelaxed());
    }

    public function testShouldGetAndSetEnvironment()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setEnvironment("HTTP_SOMETHING");
        $this->assertEquals("HTTP_SOMETHING", $auth->getEnvironment());
    }

    public function testShouldGetAndSetCookieName()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setCookie("nekot");
        $this->assertEquals("nekot", $auth->getCookie());
    }

    public function testShouldGetAndSetCallback()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setCallback(function ($decoded, $app) {
            return true;
        });
        $this->assertTrue(is_callable($auth->getCallback()));
    }

    public function testShouldGetAndSetError()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setError(function ($arguments) {
            return true;
        });
        $this->assertTrue(is_callable($auth->getError()));
    }

    public function testShoulCallError()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setError(function ($arguments) {
            return "Xevious";
        });
        $this->assertEquals("Xevious", $auth->error(array()));
    }

    public function testShouldGetAndSetRules()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $auth->setRules(array(
            function ($app) {
                return true;
            },
            function ($app) {
                return false;
            }
        ));
        $this->assertEquals(2, count($auth->getRules()));
    }

    public function testShouldSetAndGetLogger()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $logger = new \Psr\Log\NullLogger;
        $auth->setLogger($logger);

        $this->assertInstanceOf("\Psr\Log\NullLogger", $auth->getLogger());
    }

    public function testShouldSLog()
    {
        $auth = new \Slim\Middleware\JwtAuthentication;
        $logger = new \Psr\Log\NullLogger;
        $auth->setLogger($logger);
        $this->assertNull($auth->log(\Psr\Log\LogLevel::WARNING, "Token not found"));
    }

    public function testBug9ShouldAllowUnauthenticatedHttp()
    {
        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/public/foo",
            "SERVER_NAME" => "dev.example.com",
            "slim.url_scheme" => "http"
        ));
        $app = new \Slim\Slim();

        $app->get("/public/foo", function () {
            echo "Success";
        });

        $app->get("/api/foo", function () {
            echo "Foo";
        });

        $auth = new \Slim\Middleware\JwtAuthentication(array(
            "path" => array("/api", "/bar"),
            "secret" => "supersecretkeyyoushouldnotcommittogithub"
        ));

        $auth->setApplication($app);
        $auth->setNextMiddleware($app);
        $auth->call();

        $this->assertEquals(200, $app->response()->status());
        $this->assertEquals("Success", $app->response()->body());
    }
}
