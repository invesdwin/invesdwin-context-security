package de.invesdwin.context.security.web.kerberos.internal;

import java.io.IOException;

import javax.annotation.concurrent.Immutable;
import javax.servlet.GenericServlet;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import de.invesdwin.context.integration.IntegrationProperties;

@Immutable
public class ForwardToSignInServlet extends GenericServlet {

    @Override
    public void service(final ServletRequest req, final ServletResponse res) throws ServletException, IOException {
        final HttpServletResponse response = (HttpServletResponse) res;
        response.sendRedirect(IntegrationProperties.WEBSERVER_BIND_URI + "/signin");
    }

}
