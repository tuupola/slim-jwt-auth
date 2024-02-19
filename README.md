# PSR-7 and PSR-15 JWT Authentication Middleware
> [!IMPORTANT]
> This is a replacement for `tuupola/slim-jwt-auth` with the updated version of `firebase/php-jwt` to resolve
> [CVE-2021-46743](https://nvd.nist.gov/vuln/detail/CVE-2021-46743) for the meantime I plan to maintiane conpatability in v1 some,
> there is v2 I plan to deverge

This middleware implements JSON Web Token Authentication. It was originally developed for Slim but can be used with any framework using PSR-7 and PSR-15 style middlewares. It has been tested with [Slim Framework](http://www.slimframework.com/) and [Zend Expressive](https://zendframework.github.io/zend-expressive/).

[![Latest Version](https://img.shields.io/packagist/v/jimtools/jwt-auth.svg?style=flat-square)](https://packagist.org/packages/jimtools/jwt-auth)
[![Packagist](https://img.shields.io/packagist/dm/jimtools/jwt-auth.svg?style=flat-square)](https://packagist.org/packages/jimtools/jwt-auth)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)
[![Build Status](https://img.shields.io/github/actions/workflow/status/jimtools/jwt-auth/tests.yml?branch=main&style=flat-square)](https://github.com/jimtools/jwt-auth/actions)
[![Coverage](https://img.shields.io/codecov/c/gh/jimtools/jwt-auth/main.svg?style=flat-square)](https://codecov.io/github/jimtools/jwt-auth/branch/main)


Heads up! You are reading documentation for [3.x branch](https://github.com/tuupola/slim-jwt-auth/tree/3.x) which is PHP 7.4 and up only. If you are using older version of PHP see the [2.x branch](https://github.com/tuupola/slim-jwt-auth/tree/2.x). These two branches are not backwards compatible, see [UPGRADING](https://github.com/tuupola/slim-jwt-auth/blob/main/UPGRADING.md) for instructions how to upgrade.

Middleware does **not** implement OAuth 2.0 authorization server nor does it provide ways to generate, issue or store authentication tokens. It only parses and authenticates a token when passed via header or cookie. This is useful for example when you want to use [JSON Web Tokens as API keys](https://auth0.com/blog/2014/12/02/using-json-web-tokens-as-api-keys/).

For example implementation see [Slim API Skeleton](https://github.com/tuupola/slim-api-skeleton).

## Breaking Changes
Because of the way firebase/php-jwt:v6 now works, the way `secrets` and `algorithm` are pass needs to change so the following change will need to be made.

```php
$app = new Slim\App;

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "secret" => [
        "acme" => "supersecretkeyyoushouldnotcommittogithub",
        "beta" => "supersecretkeyyoushouldnotcommittogithub",
    "algorithm" => [
        "amce" => "HS256",
        "beta" => "HS384"
    ]
]));
```

## Install

Install latest version using [composer](https://getcomposer.org/).

``` bash
$ composer require jimtools/jwt-auth
```

If using Apache add the following to the `.htaccess` file. Otherwise PHP wont have access to `Authorization: Bearer` header.

``` bash
RewriteRule .* - [env=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
```

## Usage

Configuration options are passed as an array. The only mandatory parameter is `secret` which is used for verifying the token signature. Note again that `secret` is not the token. It is the secret you use to sign the token.

For simplicity's sake examples show `secret` hardcoded in code. In real life you should store it somewhere else. Good option is environment variable. You can use [dotenv](https://github.com/vlucas/phpdotenv) or something similar for development. Examples assume you are using Slim Framework.

``` php
$app = new Slim\App;

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));
```

An example where your secret is stored as an environment variable:

``` php
$app = new Slim\App;

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "secret" => getenv("JWT_SECRET")
]));
```

When a request is made, the middleware tries to validate and decode the token. If a token is not found or there is an error when validating and decoding it, the server will respond with `401 Unauthorized`.

Validation errors are triggered when the token has been tampered with or the token has expired. For all possible validation errors, see [JWT library](https://github.com/firebase/php-jwt/blob/master/src/JWT.php#L60-L138) source.


## Optional parameters
### Path

The optional `path` parameter allows you to specify the protected part of your website. It can be either a string or an array. You do not need to specify each URL. Instead think of `path` setting as a folder. In the example below everything starting with `/api` will be authenticated. If you do not define `path` all routes will be protected.

``` php
$app = new Slim\App;

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "path" => "/api", /* or ["/api", "/admin"] */
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));
```

### Ignore

With optional `ignore` parameter you can make exceptions to `path` parameter. In the example below everything starting with `/api` and `/admin`  will be authenticated with the exception of `/api/token` and `/admin/ping` which will not be authenticated.

``` php
$app = new Slim\App;

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "path" => ["/api", "/admin"],
    "ignore" => ["/api/token", "/admin/ping"],
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));
```

### Header

By default middleware tries to find the token from `Authorization` header. You can change header name using the `header` parameter.

``` php
$app = new Slim\App;

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "header" => "X-Token",
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));
```

### Regexp

By default the middleware assumes the value of the header is in `Bearer <token>` format. You can change this behaviour with `regexp` parameter. For example if you have custom header such as `X-Token: <token>` you should pass both header and regexp parameters.

``` php
$app = new Slim\App;

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "header" => "X-Token",
    "regexp" => "/(.*)/",
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));
```

### Cookie

If token is not found from neither environment or header, the middleware tries to find it from cookie named `token`. You can change cookie name using `cookie` parameter.

``` php
$app = new Slim\App;

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "cookie" => "nekot",
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));
```

### Algorithm

You can set supported algorithms via `algorithm` parameter. This can be either string or array of strings. Default value is `["HS256"]`. Supported algorithms are `HS256`, `HS384`, `HS512` and `RS256`. Note that enabling both `HS256` and `RS256` is a [security risk](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/).

When passing multiple algorithm it be a key value array, with the key being the `KID` of the jwt.

``` php
$app = new Slim\App;

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "secret" => [
        "acme" => "supersecretkeyyoushouldnotcommittogithub",
        "beta" => "supersecretkeyyoushouldnotcommittogithub",
    "algorithm" => [
        "amce" => "HS256",
        "beta" => "HS384"
    ]
]));
```

> :warning: **Warning**: <br>
Because of changes in `firebase/php-jwt` the `kid` is now checked when multiple algorithm are passed, failing to provide a key the algorithm will be used for the kid.
this also means the `kid` will now need to be present in the JWT header as well.

### Attribute

When the token is decoded successfully and authentication succeeds the contents of the decoded token is saved as `token` attribute to the `$request` object. You can change this with. `attribute` parameter. Set to `null` or `false` to disable this behavour

``` php
$app = new Slim\App;

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "attribute" => "jwt",
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));

/* ... */

$decoded = $request->getAttribute("jwt");
```

### Logger

The optional `logger` parameter allows you to pass in a PSR-3 compatible logger to help with debugging or other application logging needs.

``` php
use Monolog\Logger;
use Monolog\Handler\RotatingFileHandler;

$app = new Slim\App;

$logger = new Logger("slim");
$rotating = new RotatingFileHandler(__DIR__ . "/logs/slim.log", 0, Logger::DEBUG);
$logger->pushHandler($rotating);

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "path" => "/api",
    "logger" => $logger,
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));
```

### Before

Before function is called only when authentication succeeds but before the next incoming middleware is called. You can use this to alter the request before passing it to the next incoming middleware in the stack. If it returns anything else than `Psr\Http\Message\ServerRequestInterface` the return value will be ignored.

``` php
$app = new Slim\App;

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "secret" => "supersecretkeyyoushouldnotcommittogithub",
    "before" => function ($request, $arguments) {
        return $request->withAttribute("test", "test");
    }
]));
```

### After

After function is called only when authentication succeeds and after the incoming middleware stack has been called. You can use this to alter the response before passing it next outgoing middleware in the stack. If it returns anything else than `Psr\Http\Message\ResponseInterface` the return value will be ignored.


``` php
$app = new Slim\App;

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "secret" => "supersecretkeyyoushouldnotcommittogithub",
    "after" => function ($response, $arguments) {
        return $response->withHeader("X-Brawndo", "plants crave");
    }
]));
```

> Note that both the after and before callback functions receive the raw token string as well as the decoded claims through the `$arguments` argument.

### Error

Error is called when authentication fails. It receives last error message in arguments. You can use this for example to return JSON formatted error responses.

```php
$app = new Slim\App;

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "secret" => "supersecretkeyyoushouldnotcommittogithub",
    "error" => function ($response, $arguments) {
        $data["status"] = "error";
        $data["message"] = $arguments["message"];

        $response->getBody()->write(
            json_encode($data, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT)
        );

        return $response->withHeader("Content-Type", "application/json")
    }
]));
```

### Rules

The optional `rules` parameter allows you to pass in rules which define whether the request should be authenticated or not. A rule is a callable which receives the request as parameter. If any of the rules returns boolean `false` the request will not be authenticated.

By default middleware configuration looks like this. All paths are authenticated with all request methods except `OPTIONS`.

``` php
$app = new Slim\App;

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "rules" => [
        new Tuupola\Middleware\JwtAuthentication\RequestPathRule([
            "path" => "/",
            "ignore" => []
        ]),
        new Tuupola\Middleware\JwtAuthentication\RequestMethodRule([
            "ignore" => ["OPTIONS"]
        ])
    ]
]));
```

RequestPathRule contains both a `path` parameter and a `ignore` parameter. Latter contains paths which should not be authenticated. RequestMethodRule contains `ignore` parameter of request methods which also should not be authenticated. Think of `ignore` as a whitelist.

99% of the cases you do not need to use the `rules` parameter. It is only provided for special cases when defaults do not suffice.

## Security

JSON Web Tokens are essentially passwords. You should treat them as such and you should always use HTTPS. If the middleware detects insecure usage over HTTP it will throw a `RuntimeException`. By default this rule is relaxed for requests to server running on `localhost`. To allow insecure usage you must enable it manually by setting `secure` to `false`.

``` php
$app->add(new Tuupola\Middleware\JwtAuthentication([
    "secure" => false,
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));
```

Alternatively you could list multiple development servers to have relaxed security. With below settings both `localhost` and `dev.example.com` allow incoming unencrypted requests.

``` php
$app->add(new Tuupola\Middleware\JwtAuthentication([
    "secure" => true,
    "relaxed" => ["localhost", "dev.example.com"],
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));
```

## Authorization

By default middleware only authenticates. This is not very interesting. Beauty of JWT is you can pass extra data in the token. This data can include for example scope which can be used for authorization.

**It is up to you to implement how token data is stored or possible authorization implemented.**

Let assume you have token which includes data for scope. By default middleware saves the contents of the token to `token` attribute of the request.

``` php
[
    "iat" => "1428819941",
    "exp" => "1744352741",
    "scope" => ["read", "write", "delete"]
]
```

``` php
$app = new Slim\App;

$app->add(new Tuupola\Middleware\JwtAuthentication([
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));

$app->delete("/item/{id}", function ($request, $response, $arguments) {
    $token = $request->getAttribute("token");
    if (in_array("delete", $token["scope"])) {
        /* Code for deleting item */
    } else {
        /* No scope so respond with 401 Unauthorized */
        return $response->withStatus(401);
    }
});
```

## Testing

You can run tests either manually or automatically on every code change. Automatic tests require [entr](http://entrproject.org/) to work.

``` bash
$ make test
```

``` bash
$ brew install entr
$ make watch
```

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email tuupola@appelsiini.net instead of using the issue tracker.

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.
