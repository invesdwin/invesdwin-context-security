package de.invesdwin.context.security.web.internal;

import javax.annotation.concurrent.ThreadSafe;

import de.invesdwin.context.security.web.IntegrationSecurityWebDummyContextLocation;
import de.invesdwin.context.test.ATest;
import de.invesdwin.context.test.TestContext;
import de.invesdwin.context.test.stub.StubSupport;
import jakarta.inject.Named;

@Named
@ThreadSafe
public class IntegrationSecurityWebDummyContextLocationStub extends StubSupport {

    @Override
    public void tearDownOnce(final ATest test, final TestContext ctx) {
        if (!ctx.isFinished()) {
            return;
        }
        IntegrationSecurityWebDummyContextLocation.reset();
    }
}
