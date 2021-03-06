package de.invesdwin.context.security.ldap.directory.server;

import java.io.File;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.ContextProperties;

@NotThreadSafe
public final class DirectoryServerProperties {

    public static final File WORKING_DIR = new File(ContextProperties.getCacheDirectory(),
            DirectoryServer.class.getSimpleName());

    private DirectoryServerProperties() {}

}
