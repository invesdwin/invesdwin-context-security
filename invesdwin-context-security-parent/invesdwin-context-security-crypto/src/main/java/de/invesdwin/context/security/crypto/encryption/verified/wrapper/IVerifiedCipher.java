package de.invesdwin.context.security.crypto.encryption.verified.wrapper;

import de.invesdwin.context.security.crypto.encryption.cipher.CipherMode;
import de.invesdwin.context.security.crypto.encryption.cipher.ICipher;
import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

public interface IVerifiedCipher extends ICipher {

    /**
     * WARNING: For internal use only. Call IEncryptionFactory.init(...) or one of the higher level methods instead from
     * external code. Otherwise params are not handled properly.
     */
    @Deprecated
    int init(CipherMode mode, IKey key, IByteBuffer paramBuffer);

}
