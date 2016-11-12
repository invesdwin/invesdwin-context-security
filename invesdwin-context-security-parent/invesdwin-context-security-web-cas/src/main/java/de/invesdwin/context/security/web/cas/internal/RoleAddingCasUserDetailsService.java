package de.invesdwin.context.security.web.cas.internal;

import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;

import javax.annotation.concurrent.Immutable;
import javax.inject.Named;

import org.jasig.cas.client.validation.Assertion;
import org.springframework.security.cas.userdetails.AbstractCasAssertionUserDetailsService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import de.invesdwin.context.security.web.cas.CasProperties;

@Named
@Immutable
public class RoleAddingCasUserDetailsService extends AbstractCasAssertionUserDetailsService {

    private static final String DUMMY_PASSWORD = "_DUMMY_";

    @Override
    protected UserDetails loadUserDetails(final Assertion assertion) {
        final String username = assertion.getPrincipal().getName();

        final List<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();

        for (final Entry<String, Object> e : assertion.getPrincipal().getAttributes().entrySet()) {
            final Object value = e.getValue();

            if (value == null) {
                continue;
            }

            if (value instanceof List) {
                final List<?> list = (List<?>) value;

                for (final Object o : list) {
                    grantedAuthorities.add(new SimpleGrantedAuthority(o.toString()));
                }
            } else {
                grantedAuthorities.add(new SimpleGrantedAuthority(value.toString()));
            }

        }
        grantedAuthorities.add(new SimpleGrantedAuthority(CasProperties.ROLE_CAS_AUTHENTICATED));

        return new User(username, DUMMY_PASSWORD, grantedAuthorities);
    }
}