<?php

/**
 * This file is part of PSR-7 & PSR-15 JWT Authentication middleware
 *
 * Copyright (c) 2015-2017 Mika Tuupola
 *
 * Licensed under the MIT license:
 *   http://www.opensource.org/licenses/mit-license.php
 *
 * Project home:
 *   https://github.com/tuupola/slim-jwt-auth
 *   https://appelsiini.net/projects/slim-jwt-auth
 *
 */

namespace Tuupola\Middleware\JwtAuthentication;

use Slim\Http\Response as SlimResponse;
use Zend\Diactoros\Response as DiactorosResponse;
use GuzzleHttp\Psr7\Response as GuzzleResponse;
use Nyholm\Psr7\Response as NyholmResponse;
use Interop\Http\Factory\ResponseFactoryInterface;

final class ResponseFactory implements ResponseFactoryInterface
{
    public function createResponse($code = 200)
    {
        if (class_exists(SlimResponse::class)) {
            return new SlimResponse($code);
        }

        if (class_exists(DiactorosResponse::class)) {
            return new DiactorosResponse("php://memory", $code);
        }

        if (class_exists(GuzzleResponse::class)) {
            return new GuzzleResponse($code);
        }

        if (class_exists(NyholmResponse::class)) {
            return new NyholmResponse($code);
        }

        throw new \RuntimeException("No PSR-7 implementation available");
    }
}
