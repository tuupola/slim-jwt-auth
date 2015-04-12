# JWT Authentication Middleware for Slim

[![Latest Version](https://img.shields.io/github/release/tuupola/slim-jwt-auth.svg?style=flat-square)](https://github.com/tuupola/slim-jwt-auth/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/travis/tuupola/slim-jwt-auth/master.svg?style=flat-square)](https://travis-ci.org/tuupola/slim-jwt-auth)
[![HHVM Status](https://img.shields.io/hhvm/tuupola/slim-jwt-auth.svg?style=flat-square)](http://hhvm.h4cc.de/package/tuupola/slim-jwt-auth)
[![Coverage](http://img.shields.io/codecov/c/github/tuupola/slim-jwt-auth.svg?style=flat-square)](https://codecov.io/github/tuupola/slim-jwt-auth)

This middleware implements JSON Web Token Authentication for Slim Framework. It does **not** implement OAuth 2.0 authorization server nor does it provide ways to generate, issue or store authentication tokens. It only parses and authenticates a token when passed via header, cookie (not implemented) or querystring (not implemented). This is useful when you want to use [JSON Web Tokens as API keys](https://auth0.com/blog/2014/12/02/using-json-web-tokens-as-api-keys/).

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

With optional `path` parameter can authenticate only given part of your website.

``` php
$app = new \Slim\Slim();

$app->add(new \Slim\Middleware\JwtAuthentication([
    "path" => "/api",
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));
```

When request is made middleware tries to validate and decode the token. If token is not found server will response with `401 Unauthorized`. If token exists but there is an error when validating and decoding it server will response with `400 Bad Request`.

Validation error is triggered for example when token has been tampered or token has expired. For all possible reasons see [JWT library ](https://github.com/firebase/php-jwt/blob/master/Authentication/JWT.php#L44) source.

## Authorization

By default middleware only authenticates. This is not very interesting. Beauty of JWT is you can pass extra data in the token. This data can include for example scope which can be used for authorization.

**It is up to you to implement how token data is stored or possible authorization implemented.**

Let assume you have token which includes data for scope. In middleware callback you store the decoded token data to `$app->jwt` and later use it for authorization.

``` php
[
    "iat" => "1428819941",
    "exp" => "1744352741",
    "scope" => ["read", "write", "delete"]
]
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

## Blacklisting (not implemented yet)

Tokens are like passwords and should be treated like one. Sometimes bad things happen. Maybe you accidentally leak internal token with full admin rights scope and expiration set to 10 years. Since there is no need to store tokens in database how can you revoke one? Changing the secret key would revoke all tokens in the wild.

**Again it is up to you to implement how token blacklisting is done. This middleware intentionally only provides interface for blacklisting.**

You can blacklist tokens by passing a callable `blacklist` parameter. This callable receives the decoded token and instance of Slim application as parameters. If callable returns boolean `true` the token is assumed to be blacklisted and server will response with `401 Unauthorized`.

One way of support blacklisting is to include `jti` ([JWT ID](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html#jtiDef)) claim in the token. This claim is unique identifier for the token and can be used for blacklisting.

``` php
[
    "iat" => "1428819941",
    "exp" => "1744352741",
    "jti" => "24d4e5c5-5727-4b7f-bd1d-a8f0733f160b",
    "scope" => ["read", "write", "delete"]
]
```

``` php
$app = new \Slim\Slim();

$app->add(new \Slim\Middleware\JwtAuthentication([
    "secret" => "supersecretkeyyoushouldnotcommittogithub",
    "blacklist" => function ($decoded, $app) {
        return "24d4e5c5-5727-4b7f-bd1d-a8f0733f160b" === $decoded["jti"];
    }
]));
```

## Testing

``` bash
$ vendor/bin/phpunit
$ vendor/bin/phpcs --standard=PSR2 src/* -p
```

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email tuupola@appelsiini.net instead of using the issue tracker.

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
