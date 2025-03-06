# JWT-scanner - Burp Extension

## Description
JWT Scanner is a Burp Suite extension for automated testing of JSON Web Token (JWT) implementations of web applications. 

### Checks
- Signature presence
- Invalid signatures
- Signatures with empty passwords
- Usage of algorithm none variations
- Invalid ECDSA parameters (CVE-2022-21449)
- Jwk header injection
- Jku header injection
- Kid header path traversal
- Algorithm confusion

## Features
- Select base request and autodetection of JWT
- Manually select target JWT in source request
- Select two base request with different JWTs and try forging the public key

## Usage
Run an active scan or manually select a request from to check:

1. Go to  Proxy / Repeater / Target / Logger / Intruder
2. Select request that requires a authentication with a valid JWT and returns a HTTP 200 response

### Automatically detect JWT
1. Right-click on the request you want to check.
2. Extension -> JWT Scanner -> Scan (autodetect)
3. In case of a identified vulnerability a issue is generated

Autodetect JWT from valid request:

![](docs/auto_select.png)

### Manually select JWT
1. Highlight the target JWT in request
2. Right-click highlighted JWT request
3. Extension -> JWT Scanner -> Scan selected
4. In case of a identified vulnerability a issue is generated

Manually select JWT from valid request:

![](docs/manual_select.png)

### Forging public keys

If a public key is not exposed, you can try forge one.

1. Select two base requests each containing exactly one but different JWT
2. Right-click highlighted JWT requests
3. Extension -> JWT Scanner -> Forge public key
4. Investigate Event and Issue log
5. If successful rerun "Scan (autodetect)" or "Scan selected"

![](docs/forge_public_key.png)

## Installation
1. Download the latest pre-built jar file from [releases](https://github.com/CompassSecurity/jwt-scanner/releases).
2. Extension -> Installed -> Add -> Extension Details -> Extension Type: *Java* -> Select file ...
3. Select the downloaded jar

## Build
Using gradle to build jar:
```shell
./gradlew jar
```
