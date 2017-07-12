package com.synaltic.cxf.cert;

import org.apache.cxf.Bus;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.security.transport.TLSSessionInfo;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

import java.io.File;
import java.io.FileInputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.*;
import java.util.*;

public class CertInterceptor extends AbstractPhaseInterceptor<Message> {

    public static final String CONFIG_PID = "com.synaltic.cxf.cert";

    private BundleContext bundleContext;

    public CertInterceptor(BundleContext bundleContext) {
        this(Phase.UNMARSHAL, bundleContext);
    }

    public CertInterceptor(String phase, BundleContext bundleContext) {
        super(phase);
        this.bundleContext = bundleContext;
    }

    public void handleMessage(Message message) throws Fault {
        TLSSessionInfo tlsSession = message.get(TLSSessionInfo.class);
        if (tlsSession == null) {
            throw new SecurityException("No TLS connection");
        }

        Certificate[] certificates = tlsSession.getPeerCertificates();
        if (certificates == null || certificates.length == 0) {
            throw new SecurityException("No certificate found");
        }

        // due to RFC5246, senders certificates always come first
        Certificate certificate = certificates[0];

        // validate the certificate
        try {
            Bus bus = message.getExchange().getBus();

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(new FileInputStream(new File(getKeyStorePath(bus.getId()))), getKeyStorePassword(bus.getId()).toCharArray());

            if (!validateKeyChain((X509Certificate) certificate, keyStore)) {
                throw new SecurityException("Certificate is invalid");
            }
        } catch (Exception e) {
            throw new SecurityException("Certificate verification failed", e);
        }
    }

    private boolean validateKeyChain(X509Certificate certificate, KeyStore keyStore) throws Exception {
        X509Certificate[] certificates = new X509Certificate[keyStore.size()];
        int i = 0;
        Enumeration<String> alias = keyStore.aliases();
        while (alias.hasMoreElements()) {
            certificates[i++] = (X509Certificate) keyStore.getCertificate(alias.nextElement());
        }
        return validateKeyChain(certificate, certificates);
    }

    private boolean validateKeyChain(X509Certificate certificate, X509Certificate... trustedCertificates) throws Exception {
        boolean found = false;
        int i = trustedCertificates.length;
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        TrustAnchor anchor;
        Set anchors;
        CertPath path;
        List list;
        PKIXParameters params;
        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        while (!found && i > 0) {
            anchor = new TrustAnchor(trustedCertificates[--i], null);
            anchors = Collections.singleton(anchor);
            list = Arrays.asList(new Certificate[] { certificate });
            path = cf.generateCertPath(list);
            params = new PKIXParameters(anchors);
            params.setRevocationEnabled(false);
            if (certificate.getIssuerDN().equals(trustedCertificates[i].getSubjectDN())) {
                try {
                    validator.validate(path, params);
                    if (isSelfSigned(trustedCertificates[i])) {
                        // found root CA
                        found = true;
                    } else if (!certificate.equals(trustedCertificates[i])) {
                        found = validateKeyChain(trustedCertificates[i], trustedCertificates);
                    }
                } catch (Exception e) {
                    // validate failed, check next cert in the trust store
                }
            }
        }
        return found;
    }

    private boolean isSelfSigned(X509Certificate certificate) throws Exception {
        try {
            PublicKey key = certificate.getPublicKey();
            certificate.verify(key);
            return true;
        } catch (SignatureException signatureException) {
            return  false;
        } catch (InvalidKeyException invalidKeyException) {
            return false;
        }
    }

    private String getKeyStorePath(String busId) throws Exception {
        ServiceReference<ConfigurationAdmin> ref = bundleContext.getServiceReference(ConfigurationAdmin.class);
        if (ref != null) {
            try {
                ConfigurationAdmin configurationAdmin = bundleContext.getService(ref);
                Configuration configuration = configurationAdmin.getConfiguration(CONFIG_PID);
                if (configuration != null && configuration.getProperties() != null) {
                    return (String) configuration.getProperties().get(busId + ".keystore.path");
                }
            } finally {
                bundleContext.ungetService(ref);
            }
        }
        return null;
    }

    private String getKeyStorePassword(String busId) throws Exception {
        ServiceReference<ConfigurationAdmin> ref = bundleContext.getServiceReference(ConfigurationAdmin.class);
        if (ref != null) {
            try {
                ConfigurationAdmin configurationAdmin = bundleContext.getService(ref);
                Configuration configuration = configurationAdmin.getConfiguration(CONFIG_PID);
                if (configuration != null && configuration.getProperties() != null) {
                    return (String) configuration.getProperties().get(busId + ".keystore.password");
                }
            } finally {
                bundleContext.ungetService(ref);
            }
        }
        return null;
    }

}
