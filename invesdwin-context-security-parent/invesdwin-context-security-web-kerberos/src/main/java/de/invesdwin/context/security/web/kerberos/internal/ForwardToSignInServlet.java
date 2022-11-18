package de.invesdwin.context.security.web.kerberos.internal;

import java.io.IOException;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.context.integration.IntegrationProperties;
import jakarta.servlet.GenericServlet;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;

@Immutable
public class ForwardToSignInServlet extends GenericServlet {

    @Override
    public void service(final ServletRequest req, final ServletResponse res) throws ServletException, IOException {
        final HttpServletResponse response = (HttpServletResponse) res;
        response.sendRedirect(IntegrationProperties.WEBSERVER_BIND_URI + "/signin");
    }

}
