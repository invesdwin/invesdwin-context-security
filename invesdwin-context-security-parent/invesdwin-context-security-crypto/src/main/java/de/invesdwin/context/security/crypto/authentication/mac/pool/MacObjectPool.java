package de.invesdwin.context.security.crypto.authentication.mac.pool;

import javax.annotation.concurrent.ThreadSafe;

import de.invesdwin.util.concurrent.pool.timeout.ATimeoutObjectPool;
import de.invesdwin.util.time.date.FTimeUnit;
import de.invesdwin.util.time.duration.Duration;

@ThreadSafe
public final class MacObjectPool extends ATimeoutObjectPool<IMac> {

    private final IMacFactory factory;

    public MacObjectPool(final IMacFactory factory) {
        super(Duration.ONE_MINUTE, new Duration(10, FTimeUnit.SECONDS));
        this.factory = factory;
    }

    @Override
    protected IMac newObject() {
        return factory.newMac();
    }

    @Override
    public void invalidateObject(final IMac obj) {
        //will do a lazy reset only if required
        obj.reset();
    }

    @Override
    protected void passivateObject(final IMac element) {
        //will do a lazy reset only if required
        element.reset();
    }

}
