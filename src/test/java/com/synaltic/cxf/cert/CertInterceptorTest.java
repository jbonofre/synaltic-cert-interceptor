package com.synaltic.cxf.cert;

import org.easymock.EasyMock;
import org.junit.Test;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

import java.io.IOException;
import java.util.Dictionary;

public class CertInterceptorTest {

    @Test
    public void testIsEnabled() throws Exception {
        Configuration configuration = EasyMock.mock(Configuration.class);
    }

}
