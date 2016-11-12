package de.invesdwin.context.security.web.internal;

import javax.annotation.concurrent.NotThreadSafe;

import org.springframework.context.ApplicationContext;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.DispatcherServlet;

import de.invesdwin.context.beans.init.MergedContext;
import de.invesdwin.util.assertions.Assertions;

/**
 * ContextLoadingListener is not early enough. The springSecurityFilterChain is required immediately, so the parent has
 * to be set before the context is refreshed. Not after as it happens in most of the other modules.
 */
@NotThreadSafe
public class ChildContextDispatcherServlet extends DispatcherServlet {

    @Override
    protected WebApplicationContext createWebApplicationContext(final ApplicationContext parent) {
        Assertions.assertThat(parent).isNull();
        return super.createWebApplicationContext(MergedContext.getInstance());
    }

}
