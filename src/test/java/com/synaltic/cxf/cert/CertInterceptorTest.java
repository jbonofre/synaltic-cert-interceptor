package com.synaltic.cxf.cert;

import org.easymock.EasyMock;
import org.junit.Assert;
import org.junit.Test;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

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

}
