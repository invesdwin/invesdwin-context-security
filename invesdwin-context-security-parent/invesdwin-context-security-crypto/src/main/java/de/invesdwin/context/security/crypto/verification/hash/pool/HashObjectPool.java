package de.invesdwin.context.security.crypto.verification.hash.pool;

import javax.annotation.concurrent.ThreadSafe;

import de.invesdwin.context.security.crypto.verification.hash.IHash;
import de.invesdwin.util.concurrent.pool.timeout.ATimeoutObjectPool;
import de.invesdwin.util.time.date.FTimeUnit;
import de.invesdwin.util.time.duration.Duration;

@ThreadSafe
public final class HashObjectPool extends ATimeoutObjectPool<IHash> {

    private final IHashFactory factory;

    public HashObjectPool(final IHashFactory factory) {
        super(Duration.ONE_MINUTE, new Duration(10, FTimeUnit.SECONDS));
        this.factory = factory;
    }

    @Override
    protected IHash newObject() {
        return factory.newHash();
    }

    @Override
    public void invalidateObject(final IHash obj) {
        //will do a lazy reset only if required
        obj.reset();
    }

    @Override
    protected void passivateObject(final IHash element) {
        //will do a lazy reset only if required
        element.reset();
    }

}
