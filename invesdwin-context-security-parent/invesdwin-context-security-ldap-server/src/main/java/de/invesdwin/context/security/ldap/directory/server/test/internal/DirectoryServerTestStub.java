package de.invesdwin.context.security.ldap.directory.server.test.internal;

import java.io.IOException;
import java.util.List;

import javax.annotation.concurrent.GuardedBy;
import javax.annotation.concurrent.ThreadSafe;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;

import de.invesdwin.context.ContextDirectoriesStub;
import de.invesdwin.context.beans.init.MergedContext;
import de.invesdwin.context.beans.init.locations.PositionedResource;
import de.invesdwin.context.security.ldap.directory.server.DirectoryServer;
import de.invesdwin.context.security.ldap.directory.server.DirectoryServerContextLocation;
import de.invesdwin.context.security.ldap.directory.server.DirectoryServerProperties;
import de.invesdwin.context.security.ldap.directory.server.test.DirectoryServerTest;
import de.invesdwin.context.test.ATest;
import de.invesdwin.context.test.TestContext;
import de.invesdwin.context.test.stub.StubSupport;
import de.invesdwin.util.lang.Files;
import de.invesdwin.util.lang.reflection.Reflections;
import de.invesdwin.util.shutdown.IShutdownHook;
import de.invesdwin.util.shutdown.ShutdownHookManager;
import jakarta.inject.Named;

@Named
@ThreadSafe
public class DirectoryServerTestStub extends StubSupport {

    @GuardedBy("this.class")
    private static DirectoryServer lastServer;

    static {
        ShutdownHookManager.register(new IShutdownHook() {
            @Override
            public void shutdown() throws Exception {
                maybeStopLastServer();
            }
        });
        ContextDirectoriesStub.addProtectedDirectory(DirectoryServerProperties.WORKING_DIR);
    }

    @Override
    public void setUpContextLocations(final ATest test, final List<PositionedResource> locations) throws Exception {
        final DirectoryServerTest annotation = Reflections.getAnnotation(test, DirectoryServerTest.class);
        if (annotation != null) {
            if (annotation.value()) {
                locations.add(DirectoryServerContextLocation.CONTEXT_LOCATION);
            } else {
                locations.remove(DirectoryServerContextLocation.CONTEXT_LOCATION);
            }
        }
    }

    @Override
    public void setUpContext(final ATest test, final TestContext ctx) throws Exception {
        if (ctx.isPreMergedContext()) {
            return;
        }
        //if for some reason the tearDownOnce was not executed on the last test (maybe maven killed it?), then try to stop here aswell
        maybeStopLastServer();
        //clean up for next test
        try {
            Files.deleteDirectory(DirectoryServerProperties.WORKING_DIR);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void setUpOnce(final ATest test, final TestContext ctx) throws Exception {
        synchronized (DirectoryServerTestStub.class) {
            if (DirectoryServerTestStub.lastServer == null) {
                try {
                    DirectoryServerTestStub.lastServer = MergedContext.getInstance().getBean(DirectoryServer.class);
                } catch (final NoSuchBeanDefinitionException e) { //SUPPRESS CHECKSTYLE empty block
                    //ignore
                }
            }
        }
    }

    @Override
    public void tearDownOnce(final ATest test, final TestContext ctx) throws Exception {
        if (!ctx.isFinished()) {
            return;
        }
        maybeStopLastServer();
    }

    private static synchronized void maybeStopLastServer() throws Exception {
        if (lastServer != null) {
            lastServer.stop();
            lastServer = null;
        }
    }

}
