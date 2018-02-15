# Updgrading from 2.x to 3.x

## New namespace
For most cases it is enough just to update the classname. Instead of using the old `Slim\Middleware` namespace:

```php
$app->add(new Slim\Middleware\JwtAuthentication([
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));
```

You should now use `Tuupola\Middleware` instead:

```php
$app->add(new Tuupola\Middleware\JwtAuthentication([
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));

```

## Changed parameter names

Parameters `callback` and `passthrough` were renamed to `before` and `ignore`. In other words instead of doing:

```php
$app->add(new Tuupola\Middleware\JwtAuthentication([
    "passthrough" => ["/token"],
    "callback" => function ($request, $response, $arguments) {
        print_r($arguments);
    }
]));
```

You should now do the following instead. Note also that `$response` object is not bassed to `before` anymore. The `before` handler should return ``Psr\Http\Message\ServerRequestInterface`. Anything else will be ignored.

```php
$app->add(new Tuupola\Middleware\JwtAuthentication([
    "ignore" => ["/token"],
    "before" => function ($request, $arguments) {
        return $request->withHeader("Foo", "bar");
    }
]));
```

## Changed error handler signature

Error handler signature was changed. In other words instead of doing:

```php
$app->add(new Tuupola\Middleware\JwtAuthentication([
    "error" => function ($request, $response, $arguments) {
        print_r($arguments);
    }
]));
```

You should now do the following instead.

```php
$app->add(new Tuupola\Middleware\JwtAuthentication([
    "error" => function ($response, $arguments) {
        return $response->witHeader("Foo", "bar");
    }
]));
```

Note that `error` should now return an instance of `Psr\Http\Message\ResponseInterface`. Anything else will be ignored.

## Most setters are removed

Most public setters and getters were removed. If you had code like following:

```php
$auth = (new Tuupola\Middleware\JwtAuthentication)
    ->setPath(["/admin", "/api"])
    ->setSecret("supersecretkeyyoushouldnotcommittogithub");

$app->add($auth);
```

Settings should now be passed in constructor instead:

```php
$app->add(new Tuupola\Middleware\JwtAuthentication([
    "path" => ["/admin", "/api"],
    "secret" => "supersecretkeyyoushouldnotcommittogithub"
]));
```

## Decoded token is now an array

The decoded token attached to the `$request` object is now an array instead of an object. This might require changes to token handling code.
