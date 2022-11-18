package de.invesdwin.context.security.kerberos;

import java.io.File;
import java.net.Proxy;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.concurrent.ThreadSafe;

import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.kerberos.client.KerberosRestTemplate;

import de.invesdwin.util.lang.uri.URIs;

@ThreadSafe
public class ProxyEnabledKerberosRestTemplate extends KerberosRestTemplate {

    /**
     * This instance uses Ticket Cache
     */
    public ProxyEnabledKerberosRestTemplate() {
        this((File) null, "_DUMMY_");
    }

    public ProxyEnabledKerberosRestTemplate(final String userPrincipal, final String userPass) {
        this(Keytabs.createKeytab(userPrincipal, userPass), userPrincipal);
    }

    public ProxyEnabledKerberosRestTemplate(final File keyTabLocation, final String userPrincipal) {
        super(keyTabLocation.getAbsolutePath(), userPrincipal, createLoginOptions());
        final Proxy systemProxy = URIs.getSystemProxy();
        if (systemProxy != null) {
            final SimpleClientHttpRequestFactory requestFactory = (SimpleClientHttpRequestFactory) getRequestFactory();
            requestFactory.setProxy(systemProxy);
        }
    }

    private static Map<String, Object> createLoginOptions() {
        final Map<String, Object> options = new HashMap<String, Object>();
        options.put("debug", Boolean.toString(KerberosProperties.KERBEROS_DEBUG));
        return options;
    }

}
