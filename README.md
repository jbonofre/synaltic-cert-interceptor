# SSL Certification Interceptor

This CXF interceptor checks client SSL certificate with authorization specific to each CXF bus.

## Installation

You have to install CXF in your Karaf container:

```
karaf@root()> feature:repo-add cxf 3.1.3
karaf@root()> feature:install cxf
```

Then you can install the interceptor bundle:

```
karaf@root()> bundle:install -s mvn:com.synaltic/cert-interceptor/1.0.0-SNAPSHOT
```

## Configuration

The interceptor automatically react when a CXF bus appears (thanks to a service tracker).

It uses an unique configuration file `etc/com.synaltic.cxf.cert.cfg`. This configuration file contains the keystore configuration per CXf bus:

```
[bus_id].keystore.path=/path/to/keystore
[bus_id].keystore.password=password
```

## How does it work ?

The interceptor intercepts the incoming client TLS request.

Then, it checks if it's actually a TLS request. If not, a `SecurityException` is thrown.

If the TLS request is valid, the interceptor extracts the client certificate and check if this certificate is valid over the keystore defined for the corresponding bus.

If not, a `SecurityException` is thrown.

If yes, the request reaches the CXF service.
