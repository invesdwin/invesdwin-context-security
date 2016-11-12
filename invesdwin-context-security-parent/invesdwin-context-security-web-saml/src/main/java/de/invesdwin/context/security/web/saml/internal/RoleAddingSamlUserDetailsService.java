package de.invesdwin.context.security.web.saml.internal;

import java.util.ArrayList;
import java.util.Collection;

import javax.annotation.concurrent.Immutable;
import javax.inject.Named;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;

import de.invesdwin.context.security.web.saml.SamlProperties;

@Named
@Immutable
public class RoleAddingSamlUserDetailsService implements SAMLUserDetailsService {

    private static final String DUMMY_PASSWORD = "_DUMMY_";

    @Override
    public Object loadUserBySAML(final SAMLCredential credential) throws UsernameNotFoundException {
        final String username = credential.getNameID().getValue();

        final Collection<GrantedAuthority> gas = new ArrayList<GrantedAuthority>();
        gas.add(new SimpleGrantedAuthority(SamlProperties.ROLE_SAML_AUTHENTICATED));

        return new User(username, DUMMY_PASSWORD, gas);
    }
}