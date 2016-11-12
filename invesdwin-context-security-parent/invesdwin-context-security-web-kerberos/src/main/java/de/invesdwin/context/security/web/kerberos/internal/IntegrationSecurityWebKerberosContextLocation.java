package de.invesdwin.context.security.web.kerberos.internal;

import java.util.Arrays;
import java.util.List;

import javax.annotation.concurrent.Immutable;
import javax.inject.Named;

import org.springframework.core.io.ClassPathResource;

import de.invesdwin.context.beans.init.locations.IContextLocation;
import de.invesdwin.context.beans.init.locations.PositionedResource;
import de.invesdwin.context.beans.init.locations.PositionedResource.ResourcePosition;

@Named
@Immutable
public class IntegrationSecurityWebKerberosContextLocation implements IContextLocation {

    @Override
    public List<PositionedResource> getContextResources() {
        //load this before any http filter that has a "/**" pattern
        return Arrays.asList(PositionedResource.of(new ClassPathResource(
                "/META-INF/ctx.integration.security.web.kerberos.xml"), ResourcePosition.START));
    }

}
