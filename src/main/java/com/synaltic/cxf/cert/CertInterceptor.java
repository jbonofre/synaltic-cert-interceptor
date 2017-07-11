package com.synaltic.cxf.cert;

import org.apache.cxf.Bus;
import org.apache.cxf.interceptor.Fault;
import org.apache.cxf.message.Message;
import org.apache.cxf.phase.AbstractPhaseInterceptor;
import org.apache.cxf.phase.Phase;
import org.apache.cxf.security.transport.TLSSessionInfo;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.List;

public class CertInterceptor extends AbstractPhaseInterceptor<Message> {

    public CertInterceptor() {
        this(Phase.UNMARSHAL);
    }

    public CertInterceptor(String phase) {
        super(phase);
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
            keyStore.load(new FileInputStream(new File(System.getProperty("karaf.etc") + File.pathSeparator + bus.getId())), "password".toCharArray());

            
        } catch (Exception e) {
            throw new SecurityException("Certificate verification failed", e);
        }
    }
}
