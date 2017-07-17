package com.synaltic.cxf.cert;

import org.apache.cxf.Bus;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.util.tracker.ServiceTracker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Activator implements BundleActivator {

    private final static Logger LOG = LoggerFactory.getLogger(Activator.class);

    private ServiceTracker<Bus, ServiceRegistration> busTracker;

    public void start(final BundleContext bundleContext) throws Exception {
        LOG.debug("Starting Synaltic CXF Cert Interceptor");
        busTracker = new ServiceTracker<Bus, ServiceRegistration>(bundleContext, Bus.class, null) {

            public ServiceRegistration<?> addingService(ServiceReference<Bus> reference) {
                Bus bus = bundleContext.getService(reference);
                LOG.debug("Detected new CXF Bus " + bus.getId());
                ConfigurationAdmin configurationAdmin = null;
                ServiceReference<ConfigurationAdmin> serviceReference = bundleContext.getServiceReference(ConfigurationAdmin.class);
                if (serviceReference != null) {
                    configurationAdmin = bundleContext.getService(serviceReference);
                }
                CertInterceptor certInterceptor = new CertInterceptor(configurationAdmin);
                LOG.debug("Injecting interceptor");
                bus.getInInterceptors().add(certInterceptor);
                return null;
            }

            public void removedService(ServiceReference<Bus> reference, ServiceRegistration reg) {
                reg.unregister();
                super.removedService(reference, reg);
            }
        };
        busTracker.open();
    }

    public void stop(BundleContext bundleContext) throws Exception {
        LOG.debug("Stopping Synaltic CXF Cert Interceptor");
        if (busTracker != null) {
            busTracker.close();
        }
    }

}
