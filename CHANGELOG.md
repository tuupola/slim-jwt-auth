# Changelog

All notable changes to this project will be documented in this file, in reverse chronological order by release.

## [3.1.1](https://github.com/tuupola/slim-jwt-auth/compare/3.1.0...3.1.1) - 2018-10-12
### Added
- Support for tuupola/callable-handler:^1.0 and tuupola/http-factory:^1.0

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

