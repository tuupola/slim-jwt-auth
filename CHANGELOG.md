# Changelog

All notable changes to this project will be documented in this file, in reverse chronological order by release.

## [3.0.0](https://github.com/tuupola/slim-jwt-auth/compare/3.0.0-rc.3...2.3.3) - Unreleased
### Changed
- Namespace changed from `Slim\Middleware` to `Tuupola\Middleware`
- Middleware now uses only `Authorization` header or cookie from the PSR-7 request. The `HTTP_AUTHORIZATION` environment are now ignored.
- The `callback` setting was renamed to `before`. It is called before executing other middlewares in the stack.
- The `passthrough` setting was renamed to `ignore`.
- Public setter methods `addRule()` and `withRules()` are now immutable.

### Added
- Support for the [approved version of PSR-15](https://github.com/php-fig/http-server-middleware).
- New `after` callback. It is called after executing other middlewares in the stack.

### Removed
- Most setters and getters for settings. Pass settings in an array only during initialization.
- Support for PHP 5.X. PSR-15 is now PHP 7.x only.

