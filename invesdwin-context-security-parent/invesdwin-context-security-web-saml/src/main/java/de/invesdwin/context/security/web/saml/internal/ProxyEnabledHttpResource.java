package de.invesdwin.context.security.web.saml.internal;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Proxy.Type;

import javax.annotation.concurrent.NotThreadSafe;

import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.opensaml.util.resource.HttpResource;

import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.lang.reflection.Reflections;
import de.invesdwin.util.lang.uri.URIs;

@NotThreadSafe
public class ProxyEnabledHttpResource extends HttpResource {

    public ProxyEnabledHttpResource(final String resource) {
        super(resource);
        final Proxy systemProxy = URIs.getSystemProxy();
        if (systemProxy != null) {
            final HttpClient httpClient = Reflections.field("httpClient").ofType(HttpClient.class).in(this).get();
            final HostConfiguration hostConfiguration = httpClient.getHostConfiguration();
            final InetSocketAddress addr = (InetSocketAddress) systemProxy.address();
            Assertions.assertThat(systemProxy.type()).isEqualTo(Type.HTTP);
            hostConfiguration.setProxy(addr.getHostName(), addr.getPort());
        }
    }
}
