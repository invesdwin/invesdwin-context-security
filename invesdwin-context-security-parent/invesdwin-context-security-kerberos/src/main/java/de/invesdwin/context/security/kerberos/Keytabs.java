package de.invesdwin.context.security.kerberos;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.annotation.concurrent.NotThreadSafe;

import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.crypto.EncryptionHandler;
import org.apache.kerby.kerberos.kerb.keytab.Keytab;
import org.apache.kerby.kerberos.kerb.keytab.KeytabEntry;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;

import de.invesdwin.context.ContextProperties;
import de.invesdwin.util.assertions.Assertions;
import de.invesdwin.util.lang.Files;
import de.invesdwin.util.lang.string.UniqueNameGenerator;

@NotThreadSafe
public final class Keytabs {

    private static final UniqueNameGenerator UNIQUE_NAME_GENERATOR = new UniqueNameGenerator();

    private Keytabs() {}

    public static File createKeytab(final String principalName, final String passPhrase) {
        final Map<String, String> principalName_passPhrase = new HashMap<String, String>();
        principalName_passPhrase.put(principalName, passPhrase);
        return createKeytab(principalName_passPhrase);
    }

    public static File createKeytab(final String principalName, final String passPhrase, final File file) {
        final Map<String, String> principalName_passPhrase = new HashMap<String, String>();
        principalName_passPhrase.put(principalName, passPhrase);
        return createKeytab(principalName_passPhrase, file);
    }

    public static File createKeytab(final Map<String, String> principalName_passPhrase) {
        final File file = new File(ContextProperties.TEMP_DIRECTORY,
                Keytabs.class.getSimpleName() + "/" + UNIQUE_NAME_GENERATOR.get("keyab") + ".keytab");
        return createKeytab(principalName_passPhrase, file);
    }

    public static File createKeytab(final Map<String, String> principalName_passPhrase, final File file) {
        final KerberosTime timeStamp = new KerberosTime();

        final Keytab keytab = new Keytab();
        final List<KeytabEntry> entries = new ArrayList<KeytabEntry>();

        for (final Entry<String, String> e : principalName_passPhrase.entrySet()) {
            final String principalNameStr = e.getKey();
            Assertions.assertThat(principalNameStr).endsWith("@" + KerberosProperties.KERBEROS_PRIMARY_REALM);
            final String passPhrase = e.getValue();
            final PrincipalName principalName = new PrincipalName(principalNameStr, NameType.NT_PRINCIPAL);
            for (final EncryptionType eType : KerberosProperties.getEncryptionTypes()) {
                try {
                    final EncryptionKey encKey = EncryptionHandler.string2Key(principalNameStr, passPhrase, eType);
                    encKey.setKvno(1);
                    entries.add(new KeytabEntry(principalName, timeStamp, encKey.getKvno(), encKey));
                } catch (final KrbException e1) {
                    continue;
                }
            }
        }
        keytab.addKeytabEntries(entries);
        try {
            Files.forceMkdir(file.getParentFile());
            keytab.store(file);
        } catch (final IOException e1) {
            throw new RuntimeException(e1);
        }
        return file;
    }

}
