# JWT-scanner - Burp Extension

## Description
JWT Scanner is a Burp Suite extension for automated testing of JSON Web Token (JWT) implementations of web applications. 

### Checks
- Signature presence
- Invalid signatures
- Signatures with empty passwords
- Usage of algorithm none variations
- Invalid ECDSA parameters (CVE-2022-21449)
- JWT JWK injection

## Features
- Select base request and autodetection of JWT
- Manually select target JWT in source request

## Usage
Run an active scan or manually select a request from to check:

1. Go to  Proxy / Repeater / Target / Logger / Intruder
2. Select request that requires a authentication with a valid JWT and returns a HTTP 200 response
> **_NOTE:_** First the extension will resend the selected request without modification and check if the JWT is still valid. If not a Error will be displayed in the Event Log

### Automatically detect JWT
3. Right-click on the request you want to check.
4. Extension -> JWT-scanner -> Autodetect JWT
5. In case of a identified vulnerability a issue is generated

Autodetect JWT from valid request:

![img.png](docs/autoselect.png)

### Manually select JWT
3. Highlight the target JWT in request
4. Right-click highlighted JWT request
5. Extension -> JWT-scanner -> Selected JWT
6. In case of a identified vulnerability a issue is generated

## Installation
1. Download the latest pre-built jar file from [releases](https://github.com/CompassSecurity/jwt-scanner/releases).
2. Extension -> Installed -> Add -> Extension Details -> Extension Type: *Java* -> Select file ...
3. Select the downloaded jar

Manually select JWT from valid request:

![img_1.png](docs/manualselect.png)

## Build
Using gradle to build jar:
```shell
./gradlew jar
```
