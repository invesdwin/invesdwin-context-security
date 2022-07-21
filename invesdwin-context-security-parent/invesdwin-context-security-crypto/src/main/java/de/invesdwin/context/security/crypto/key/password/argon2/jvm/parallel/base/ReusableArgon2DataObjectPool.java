package de.invesdwin.context.security.crypto.key.password.argon2.jvm.parallel.base;

import javax.annotation.concurrent.ThreadSafe;

import de.invesdwin.util.concurrent.pool.AAgronaObjectPool;

@ThreadSafe
public class ReusableArgon2DataObjectPool extends AAgronaObjectPool<ReusableArgon2Data> {

    private final int parallelism;
    private final int memoryBlocks;

    public ReusableArgon2DataObjectPool(final int parallelism, final int memoryBlocks) {
        this.parallelism = parallelism;
        this.memoryBlocks = memoryBlocks;
    }

    @Override
    protected ReusableArgon2Data newObject() {
        return new ReusableArgon2Data(parallelism, memoryBlocks);
    }

    @Override
    protected void passivateObject(final ReusableArgon2Data element) {
        element.clear();
    }

}
