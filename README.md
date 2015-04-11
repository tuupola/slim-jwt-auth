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

``` php
$app = new \Slim\Slim();
$app->add(new \Slim\Middleware\JwtAuthentication([
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));

$app->get("/hello", function () use ($app) {
    print_r($app->jwt->data());
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
