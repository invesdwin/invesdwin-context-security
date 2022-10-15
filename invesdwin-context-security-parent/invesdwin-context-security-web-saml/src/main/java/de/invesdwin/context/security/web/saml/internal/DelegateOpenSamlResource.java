package de.invesdwin.context.security.web.saml.internal;

import java.io.IOException;
import java.io.InputStream;

import javax.annotation.concurrent.NotThreadSafe;

import org.apache.commons.io.IOUtils;
import org.joda.time.DateTime;
import org.opensaml.util.resource.ClasspathResource;
import org.opensaml.util.resource.FilesystemResource;
import org.opensaml.util.resource.Resource;
import org.opensaml.util.resource.ResourceException;

import de.invesdwin.context.integration.retry.Retry;
import de.invesdwin.util.lang.string.Strings;

@NotThreadSafe
public class DelegateOpenSamlResource implements Resource {

    private final Resource delegate;

    public DelegateOpenSamlResource(final String path) throws ResourceException {
        this(pathToResource(path));
    }

    public DelegateOpenSamlResource(final Resource delegate) {
        this.delegate = delegate;
    }

    private static Resource pathToResource(final String path) throws ResourceException {
        if (path.startsWith("classpath:")) {
            return new ClasspathResource(Strings.removeLeading(path, "classpath:"));
        } else if (Strings.startsWithAny(path, "http://", "https://")) {
            return new ProxyEnabledHttpResource(path);
        } else {
            return new FilesystemResource(path);
        }
    }

    @Override
    public String getLocation() {
        return delegate.getLocation();
    }

    @Retry(/* helps with HttpResource */)
    @Override
    public boolean exists() throws ResourceException {
        return delegate.exists();
    }

    @Retry(/* helps with HttpResource */)
    @Override
    public InputStream getInputStream() throws ResourceException {
        try {
            return IOUtils.toBufferedInputStream(delegate.getInputStream());
        } catch (final IOException e) {
            throw new ResourceException(e);
        }
    }

    @Retry(/* helps with HttpResource */)
    @Override
    public DateTime getLastModifiedTime() throws ResourceException {
        return delegate.getLastModifiedTime();
    }

}
