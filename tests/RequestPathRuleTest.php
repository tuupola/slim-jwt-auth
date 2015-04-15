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

use \Slim\Middleware\JwtAuthentication\RequestPathRule;

class MatchPathTest extends \PHPUnit_Framework_TestCase
{

    public function testShouldAuthenticateEverything()
    {
        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/"
        ));

        $rule = new RequestPathRule(array("path" => "/"));
        $this->assertTrue($rule(new \Slim\Slim));

        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/admin/"
        ));
        $this->assertTrue($rule(new \Slim\Slim));
    }


    public function testShouldAuthenticateOnlyAdmin()
    {
        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/"
        ));

        $rule = new RequestPathRule(array("path" => "/admin"));
        $this->assertFalse($rule(new \Slim\Slim));

        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/admin/"
        ));
        $this->assertTrue($rule(new \Slim\Slim));
    }

    public function testShouldPassthroughLogin()
    {
        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/admin/protected"
        ));

        $rule = new RequestPathRule(array(
            "path" => "/admin",
            "passthrough" => array("/admin/login")
        ));
        $this->assertTrue($rule(new \Slim\Slim));

        \Slim\Environment::mock(array(
            "SCRIPT_NAME" => "/index.php",
            "PATH_INFO" => "/admin/login"
        ));
        $this->assertFalse($rule(new \Slim\Slim));
    }
}
