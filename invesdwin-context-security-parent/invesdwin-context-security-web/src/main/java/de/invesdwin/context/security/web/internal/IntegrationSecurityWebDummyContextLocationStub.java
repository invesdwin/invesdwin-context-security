package de.invesdwin.context.security.web.internal;

import javax.annotation.concurrent.NotThreadSafe;
import jakarta.inject.Named;

import de.invesdwin.context.security.web.IntegrationSecurityWebDummyContextLocation;
import de.invesdwin.context.test.ATest;
import de.invesdwin.context.test.stub.StubSupport;

@Named
@NotThreadSafe
public class IntegrationSecurityWebDummyContextLocationStub extends StubSupport {

    @Override
    public void tearDownOnce(final ATest test) throws Exception {
        IntegrationSecurityWebDummyContextLocation.reset();
    }
}
