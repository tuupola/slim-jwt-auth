# Changelog

All notable changes to this project will be documented in this file, in reverse chronological order by release.

## 2.3.3 - 2017-07-12
### Added

- Support for `firebase/php-jwt:^5.0`.

## 2.3.2 - 2017-02-27

This is a security release.

`RequestPathRule` now removes multiple slashes from the URI before determining whether the path should be authenticated or not. For HTTP client `/foo` and `//foo` are different URIs and technically valid according to [RFC3986](https://tools.ietf.org/html/rfc3986). However on serverside it depends on implementation and often `/foo`, `//foo` and even `/////foo` are considered a same route.

Different PSR-7 implementations were behaving in different way. Diactoros [removes multiple leading slashes](https://github.com/zendframework/zend-diactoros/blob/master/CHANGELOG.md#104---2015-06-23). By default Slim does not alter any slashes. However when installed in subfolder [Slim removes all slashes](https://github.com/slimphp/Slim/issues/1554).

This means if you are authenticating a subfolder, for example `/api` and Slim is installed in document root it was possible to bypass authentication by doing a request to `//api`. Problem did not exist if Slim was installed in subfolder. Diactoros was not affected.

```php
$app->add(new \Slim\Middleware\JwtAuthentication([
    "path" => "/api",
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));
```

If you were using default setting of authenticating all routes you were not affected.

```php
$app->add(new \Slim\Middleware\JwtAuthentication([
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));
```

### Fixed

- Bug [#50](https://github.com/tuupola/slim-jwt-auth/issues/50) where in some cases it was possible to bypass authentication by adding multiple slashes to request URI.

