# Yubico PHP Client

### Installation

Add the `yubico/yubico-php-client` package to your `require` section in your `composer.json`

```js
{
    // ...
    "require": {
        // ...
        "yubico/yubico-php-client": "~2.0.0"
    }
}
```

### Usage

A Quick Example:

```php
$otp = "ccbbddeertkrctjkkcglfndnlihhnvekchkcctif";

// Generate a new id+key from https://api.yubico.com/get-api-key/
$yubi = new \Yubico\YubiCloud('42', 'FOOBAR=');

try {
    $auth = $yubi->verify($otp);
    echo "<p>You are authenticated!";
} catch (\Exception $e) {
    echo "<p>Authentication failed: ".$auth->getMessage();
    echo "<p>Debug output from server: ".$yubi->getLastResponse();
}
```