# JWT Authentication Middleware for Slim

[![Latest Version](https://img.shields.io/github/release/tuupola/slim-jwt-auth.svg?style=flat-square)](https://github.com/tuupola/slim-jwt-auth/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/travis/tuupola/slim-jwt-auth/master.svg?style=flat-square)](https://travis-ci.org/tuupola/slim-jwt-auth)
[![HHVM Status](https://img.shields.io/hhvm/tuupola/slim-jwt-auth.svg?style=flat-square)](http://hhvm.h4cc.de/package/tuupola/slim-jwt-auth)
[![Coverage](http://img.shields.io/codecov/c/github/tuupola/slim-jwt-auth.svg?style=flat-square)](https://codecov.io/github/tuupola/slim-jwt-auth)
[![Total Downloads](https://img.shields.io/packagist/dt/tuupola/slim-jwt-auth.svg?style=flat-square)](https://packagist.org/packages/tuupola/slim-jwt-auth)

This middleware implements JSON Web Token Authentication for Slim Framework. It does **not** implement OAuth 2.0 authorization server nor does it provide ways to generate, issue or store authentication tokens. It only parses and authenticates a token when passed via header, cookie or querystring. This is useful when you want to use [JSON Web Tokens as API keys](https://auth0.com/blog/2014/12/02/using-json-web-tokens-as-api-keys/).

## Install

You can install latest version using [composer](https://getcomposer.org/).

``` bash
$ composer require tuupola/slim-jwt-auth
```

## Usage

Configuration options are passed as an array. Only mandatory parameter is `secret` which is used for verifying then token signature. For simplicitys sake examples show `secret` hardcoded in code. In real life you should use [dotenv](https://github.com/vlucas/phpdotenv) or something similar instead.

``` php
$app = new \Slim\Slim();

$app->add(new \Slim\Middleware\JwtAuthentication([
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));
```

When request is made middleware tries to validate and decode the token. If token is not found server will response with `401 Unauthorized`. If token exists but there is an error when validating and decoding it server will response with `400 Bad Request`.

Validation error is triggered for example when token has been tampered or token has expired. For all possible reasons see [JWT library ](https://github.com/firebase/php-jwt/blob/master/Authentication/JWT.php#L44) source.

By default middleware only authenticates. This is not very interesting. Beauty of JWT is you can pass extra data in the token. This data can include for example scope which can be used for authorization. It is up to you to implement how token data is stored or possible authorization implemented.

Let assume you have token which includes data for scope. In middleware callback you store the decoded token data to `$app->jwt` and later use it for authorization.

``` php
"iss" => "Acme Toothpics Ltd",
"iat" => "1428819941",
"exp" => "1744352741",
"aud" => "www.example.com",
"sub" => "someone@example.com",
"scope" => ["read", "write", "delete"]
```

``` php
$app = new \Slim\Slim();

$app->add(new \Slim\Middleware\JwtAuthentication([
    "secret" => "supersecretkeyyoushouldnotcommittogithub",
    "callback" => function ($decoded, $app) {
        $app->jwt = $decoded;
    }
]));

$app->delete("/item/:id", function () use ($app) {
    if (in_array("delete", $app->jwt->scope)) {
        /* Code for deleting item */
    } else {
        /* No scope so respond with 401 Unauthorized */
        $this->app->response->status(401);
    }
});
```

## Testing

``` bash
$ phpunit
```

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email tuupola@appelsiini.net instead of using the issue tracker.

## Credits

- [Mika Tuupola](https://github.com/tuupola)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
