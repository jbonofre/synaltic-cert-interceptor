package com.synaltic.cxf.cert;

import org.apache.cxf.Bus;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.ServiceRegistration;
import org.osgi.util.tracker.ServiceTracker;

public class Activator implements BundleActivator {

    private ServiceTracker<Bus, ServiceRegistration> busTracker;

    public void start(final BundleContext bundleContext) throws Exception {
        busTracker = new ServiceTracker<Bus, ServiceRegistration>(bundleContext, Bus.class, null) {

            public ServiceRegistration<?> addingService(ServiceReference<Bus> reference) {
                Bus bus = bundleContext.getService(reference);
                CertInterceptor certInterceptor = new CertInterceptor();
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
        if (busTracker != null) {
            busTracker.close();
        }
    }

}
