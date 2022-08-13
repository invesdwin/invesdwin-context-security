package de.invesdwin.context.security.crypto.verification.signature.wrapper;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

import javax.annotation.concurrent.NotThreadSafe;

import de.invesdwin.context.security.crypto.key.IKey;
import de.invesdwin.context.security.crypto.verification.hash.HashMode;
import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.context.security.crypto.verification.hash.algorithm.IHashAlgorithm;
import de.invesdwin.context.security.crypto.verification.signature.SignatureKey;
import de.invesdwin.util.error.UnknownArgumentException;
import de.invesdwin.util.streams.buffer.bytes.ByteBuffers;
import de.invesdwin.util.streams.buffer.bytes.IByteBuffer;

@NotThreadSafe
public class JceSignatureHash implements IHash {

    private final Signature signature;
    private final int hashSize;
    private final boolean dynamicHashSize;
    private HashMode prevMode;
    private IKey prevKey;

    public JceSignatureHash(final String algorithm, final int hashSize) {
        this(getJceSignatureInstance(algorithm), hashSize);
    }

    public JceSignatureHash(final Signature signature, final int hashSize) {
        this.signature = signature;
        this.hashSize = hashSize;
        this.dynamicHashSize = hashSize <= IHashAlgorithm.DYNAMIC_HASH_SIZE;
    }

    public static Signature getJceSignatureInstance(final String algorithm) {
        try {
            return Signature.getInstance(algorithm);
        } catch (final NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String getAlgorithm() {
        return signature.getAlgorithm();
    }

    @Override
    public boolean isDynamicHashSize() {
        return dynamicHashSize;
    }

    @Override
    public int getHashSize() {
        return hashSize;
    }

    @Override
    public void init(final HashMode mode, final IKey key) {
        this.prevMode = mode;
        this.prevKey = key;
        try {
            final SignatureKey cKey = (SignatureKey) key;
            switch (mode) {
            case Sign:
                signature.initSign(cKey.getSignKey());
                break;
            case Verify:
                signature.initVerify(cKey.getVerifyKey());
                break;
            default:
                throw UnknownArgumentException.newInstance(HashMode.class, mode);
            }
        } catch (final InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void update(final byte input) {
        try {
            signature.update(input);
        } catch (final SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void update(final java.nio.ByteBuffer input) {
        try {
            signature.update(input);
        } catch (final SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void update(final byte[] input) {
        try {
            signature.update(input);
        } catch (final SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void update(final byte[] input, final int inputOffset, final int inputLen) {
        try {
            signature.update(input, inputOffset, inputLen);
        } catch (final SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] doFinal() {
        if (prevMode != HashMode.Sign) {
            throw new IllegalStateException("Only available for " + HashMode.class.getSimpleName() + "."
                    + HashMode.Sign.name() + ": " + prevMode);
        }
        try {
            if (isDynamicHashSize()) {
                final byte[] signed = signature.sign();
                final IByteBuffer signedSizedBuffer = ByteBuffers.allocate(signed.length + Integer.BYTES);
                signedSizedBuffer.putBytes(0, signed);
                signedSizedBuffer.putInt(signed.length, signed.length);
                return signedSizedBuffer.asByteArray();
            } else {
                return signature.sign();
            }
        } catch (final SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] doFinal(final byte[] input) {
        update(input);
        return doFinal();
    }

    @Override
    public int doFinal(final byte[] output, final int offset) {
        if (prevMode != HashMode.Sign) {
            throw new IllegalStateException("Only available for " + HashMode.class.getSimpleName() + "."
                    + HashMode.Sign.name() + ": " + prevMode);
        }
        try {
            if (isDynamicHashSize()) {
                final int signedLength = signature.sign(output, offset, output.length - offset);
                final IByteBuffer wrappedOutput = ByteBuffers.wrap(output);
                wrappedOutput.putInt(offset + signedLength, signedLength);
                return signedLength + Integer.BYTES;
            } else {
                return signature.sign(output, offset, output.length - offset);
            }
        } catch (final SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void reset() {
        init(prevMode, prevKey);
    }

    @Override
    public void close() {
        prevMode = null;
        prevKey = null;
    }

    @Override
    public boolean verify(final byte[] input, final byte[] signature) {
        update(input);
        try {
            return this.signature.verify(signature);
        } catch (final SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean verify(final IByteBuffer input, final IByteBuffer signature) {
        update(input);
        try {
            return this.signature.verify(signature.asByteArray());
        } catch (final SignatureException e) {
            throw new RuntimeException(e);
        }
    }

}
