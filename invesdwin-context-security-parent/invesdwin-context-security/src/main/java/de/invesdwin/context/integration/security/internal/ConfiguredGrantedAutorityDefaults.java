package de.invesdwin.context.integration.security.internal;

import javax.annotation.concurrent.Immutable;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.core.GrantedAuthorityDefaults;

@Immutable
@Configuration
public class ConfiguredGrantedAutorityDefaults {

    @Bean
    public GrantedAuthorityDefaults grantedAuthorityDefaults() {
        return new GrantedAuthorityDefaults(DefaultRolePrefixRemover.DISABLED_ROLE_PREFIX);
    }

}
