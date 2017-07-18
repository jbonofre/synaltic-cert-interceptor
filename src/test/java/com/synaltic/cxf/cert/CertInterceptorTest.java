package com.synaltic.cxf.cert;

import org.apache.cxf.Bus;
import org.apache.cxf.bus.CXFBusFactory;
import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Test;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Dictionary;
import java.util.Hashtable;

public class CertInterceptorTest {

    @Test
    public void testBusIdProperties() throws Exception {
        Dictionary<String, Object> properties = new Hashtable<String, Object>();
        properties.put("test.enabled", "true");
        properties.put("test.keystore.path", "/foo");
        properties.put("test.keystore.password", "test");
        Configuration configuration = EasyMock.mock(Configuration.class);
        EasyMock.expect(configuration.getProperties()).andReturn(properties).anyTimes();
        EasyMock.replay(configuration);

        ConfigurationAdmin configurationAdmin = EasyMock.mock(ConfigurationAdmin.class);
        EasyMock.expect(configurationAdmin.getConfiguration("com.synaltic.cxf.cert")).andReturn(configuration).anyTimes();
        EasyMock.replay(configurationAdmin);

        CertInterceptor interceptor = new CertInterceptor(configurationAdmin);

        Assert.assertTrue(interceptor.isEnabled("test"));
        Assert.assertEquals("/foo", interceptor.getKeyStorePath("test"));
        Assert.assertEquals("test", interceptor.getKeyStorePassword("test"));
    }

    @Test
    public void testBusIdPropertiesWithRegex() throws Exception {
        Dictionary<String, Object> properties = new Hashtable<String, Object>();
        properties.put("te.*.enabled", "true");
        properties.put("te.*.keystore.path", "/foo");
        properties.put("te.*.keystore.password", "test");
        Configuration configuration = EasyMock.mock(Configuration.class);
        EasyMock.expect(configuration.getProperties()).andReturn(properties).anyTimes();
        EasyMock.replay(configuration);

        ConfigurationAdmin configurationAdmin = EasyMock.mock(ConfigurationAdmin.class);
        EasyMock.expect(configurationAdmin.getConfiguration("com.synaltic.cxf.cert")).andReturn(configuration).anyTimes();
        EasyMock.replay(configurationAdmin);

        CertInterceptor interceptor = new CertInterceptor(configurationAdmin);

        Assert.assertTrue(interceptor.isEnabled("test"));
        Assert.assertEquals("/foo", interceptor.getKeyStorePath("test"));
        Assert.assertEquals("test", interceptor.getKeyStorePassword("test"));
    }

    @Test
    public void testSelfSignedCert() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(new FileInputStream(new File("target/test-classes/client.jks")), "password".toCharArray());

        Certificate certificate = keyStore.getCertificate("client");

        CertInterceptor interceptor = new CertInterceptor(null);

        Assert.assertTrue(interceptor.isSelfSigned((X509Certificate) certificate));
    }

    @Test
    public void testClientCertRetrieval() throws Exception {
        Bus testBus = CXFBusFactory.newInstance().createBus();

        Dictionary<String, Object> properties = new Hashtable<String, Object>();
        properties.put(".*.enabled", "true");
        properties.put(".*.keystore.path", "target/test-classes/keystore.jks");
        properties.put(".*.keystore.password", "password");
        Configuration configuration = EasyMock.mock(Configuration.class);
        EasyMock.expect(configuration.getProperties()).andReturn(properties).anyTimes();
        EasyMock.replay(configuration);

        ConfigurationAdmin configurationAdmin = EasyMock.mock(ConfigurationAdmin.class);
        EasyMock.expect(configurationAdmin.getConfiguration("com.synaltic.cxf.cert")).andReturn(configuration).anyTimes();
        EasyMock.replay(configurationAdmin);

        CertInterceptor interceptor = new CertInterceptor(configurationAdmin);

        testBus.getInInterceptors().add(interceptor);


    }

}
