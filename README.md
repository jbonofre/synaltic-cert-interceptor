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
[bus_id].enabled=true
[bus_id].keystore.path=/path/to/keystore
[bus_id].keystore.password=password
```

## How does it work ?

The interceptor intercepts the incoming client TLS request.

Then, it checks if it's actually a TLS request. If not, a `SecurityException` is thrown.

If the TLS request is valid, the interceptor extracts the client certificate and check if this certificate is valid over the keystore defined for the corresponding bus.

If not, a `SecurityException` is thrown.

If yes, the request reaches the CXF service.

### Requirements

The first thing to do is to create a client certificate in a client keystore:

```
keytool -keygen -keyalg RSA -alias client -keysize 2048 -validity 365 -keystore client.jks
```

Then, you can export just the certificate:

```
keytool -export -rfc -alias client -file client.cert -keystore client.jks
```

Now, we create a keystore to trust the client certificate:

```
keytool -import -trustcacerts -alias client -file client.cer -keystore truststore.jks
```

In order to retrieve the client cert, you have to enable client authentication on the Pax Web side using the trust store. Edit `etc/org.ops4j.pax.web.cfg` and define:


```
org.ops4j.pax.web.ssl.clientauthwanted=true
org.ops4j.pax.web.ssl.truststore=/path/to/truststore.jks
org.ops4j.pax.web.ssl.trustsore.password=password
```

NB: if you want to use the client certificate in Chrome or Firefox, you have to convert the JKS keystore to PKCS12 keystore:

```
keytool -importkeystore -srckeystore client.jks -srcstoretype JKS -destkeystore client.pfx -deststoretype PKCS12
```

You can import the PKCS12 keystore in Chrome or Firefox and access to the service. Then, the browser will display a popup allowing you to choose the certificate.
