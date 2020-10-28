# Changelog

All notable changes to this project will be documented in this file, in reverse chronological order by release.


## [3.5.1](https://github.com/tuupola/slim-jwt-auth/compare/3.5.0...3.5.1) - 2020-10-28
### Changed
- Force atleast tuupola/http-factory:1.0.2 ([#193](https://github.com/tuupola/slim-jwt-auth/issues/193)) ([#194](https://github.com/tuupola/slim-jwt-auth/pull/194)).

## [3.5.0](https://github.com/tuupola/slim-jwt-auth/compare/3.4.0...3.5.0) - 2020-09-24
### Added
- Possibility to use `ArrayAccess` objects as the `secret` ([#174](https://github.com/tuupola/slim-jwt-auth/pull/174)).
- Given `regexp` is also used when extracting token from cookie ([#171](https://github.com/tuupola/slim-jwt-auth/pull/171)).
- Allow installing with PHP 8 ([#191](https://github.com/tuupola/slim-jwt-auth/pull/191)).

## [3.4.0](https://github.com/tuupola/slim-jwt-auth/compare/3.3.0...3.4.0) - 2019-07-01
### Added
- Raw token to `before` and `after` arguments ([#168](https://github.com/tuupola/slim-jwt-auth/pull/168)).

### Removed
- Cookie contents from debug log ([#166](https://github.com/tuupola/slim-jwt-auth/pull/166)).

## [3.3.0](https://github.com/tuupola/slim-jwt-auth/compare/3.2.0...3.3.0) - 2019-03-11
### Changed
- Relaxed the typehinting of `error`, `before` and `after` handlers from `Closure` to `callable`. This allows the usage of invokable classes and array notation callables in addition to anonymous functions.
  ```php
  $middleware = new JwtAuthentication([
      "secret" => "supersecretkeyyoushouldnotcommit",
      "error" => new SomeErrorHandler
  ]);

  $middleware = new JwtAuthentication([
      "secret" => "supersecretkeyyoushouldnotcommit",
      "error" => [SomeErrorHandler::class, "error"]
  ]);
  ```

### Added
- The `error` handler now receives the request uri in the `$arguments` array. This is a workaround for [#96](https://github.com/tuupola/slim-jwt-auth/issues/96) which will be fixed in `4.x`.
  ```php
  $middleware = new JwtAuthentication([
      "secret" => "supersecretkeyyoushouldnotcommit",
      "error" => function ($response, $arguments) {
          print_r(arguments["uri"]);
      }
  ]);
  ```

### Fixed
- Cookie was ignored if using `/(.*)/` as regexp and the configured header was missing from request ([#156](https://github.com/tuupola/slim-jwt-auth/pull/156), [#158](https://github.com/tuupola/slim-jwt-auth/pull/158)).

## [3.2.0](https://github.com/tuupola/slim-jwt-auth/compare/3.1.1...3.2.0) - 2019-01-26

### Fixed
- Ignore rules were ignored if path was not given in settings ([#118](https://github.com/tuupola/slim-jwt-auth/issues/118), [#120](https://github.com/tuupola/slim-jwt-auth/pull/120)).

### Added
- Support for multiple secret keys. If an array of secret keys is given, middleware will choose the key based on `kid` claim in the token header.
  ```php
  $middleware = new JwtAuthentication([
      "secret" => [
          "acme" =>"supersecretkeyyoushouldnotcommittogithub",
          "beta" =>"anothersecretkeyfornevertocommittogithub"
      ]
  ]);
  ```
  ```json
  {
    "typ": "JWT",
    "alg": "HS256",
    "kid": "acme"
  }
  ```

## [3.1.1](https://github.com/tuupola/slim-jwt-auth/compare/3.1.0...3.1.1) - 2018-10-12
### Added
- Support for `tuupola/callable-handler:^1.0` and `tuupola/http-factory:^1.0`.

## [3.1.0](https://github.com/tuupola/slim-jwt-auth/compare/3.0.0...3.1.0) - 2018-08-07
### Added
- Support for the stable version of PSR-17

## [3.0.0](https://github.com/tuupola/slim-jwt-auth/compare/2.3.3...3.0.0) - 2018-03-02

### Changed
- Namespace changed from `Slim\Middleware` to `Tuupola\Middleware`
- Middleware now uses only `Authorization` header or cookie from the PSR-7 request. The `HTTP_AUTHORIZATION` environment are now ignored.
- The `callback` setting was renamed to `before`. It is called before executing other middlewares in the stack.
- The `passthrough` setting was renamed to `ignore`.
- Public setter methods `addRule()` and `withRules()` are now immutable.
- Error callback now receives only response and arguments, request was removed.
- Before callback now receives only request and arguments, response was removed.
- After callback now receives only response and arguments, request was removed.
- PHP 7.1 is now minimal requirement.
- The decoded token is now an array instead of object.

### Added
- Support for the [approved version of PSR-15](https://github.com/php-fig/http-server-middleware).
- New `after` callback. It is called after executing other middlewares in the stack.

### Removed
- Most setters and getters for settings. Pass settings in an array only during initialization.

