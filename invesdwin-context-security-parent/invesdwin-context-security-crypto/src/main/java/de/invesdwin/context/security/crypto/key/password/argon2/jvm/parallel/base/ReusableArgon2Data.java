package de.invesdwin.context.security.crypto.key.password.argon2.jvm.parallel.base;

import java.util.concurrent.Future;

import javax.annotation.concurrent.NotThreadSafe;

@NotThreadSafe
public class ReusableArgon2Data {

    private final Future<?>[] futures;
    private final long[][] blockMemory;
    private final Blake2b blake2b;

    public ReusableArgon2Data(final int parallelism, final int memoryBlocks) {
        this.futures = new Future[parallelism];
        blockMemory = new long[memoryBlocks][FastArgon2Function.ARGON2_QWORDS_IN_BLOCK];
        for (int i = 0; i < memoryBlocks; i++) {
            blockMemory[i] = new long[FastArgon2Function.ARGON2_QWORDS_IN_BLOCK];
        }
        this.blake2b = new Blake2b();
    }

    public Future<?>[] getFutures() {
        return futures;
    }

    public long[][] getBlockMemory() {
        return blockMemory;
    }

    public void clear() {
        //        for (final long[] block : blockMemory) {
        //            Arrays.fill(block, 0);
        //        }
        //        Arrays.fill(futures, null);
    }

    public Blake2b getBlake2b() {
        return blake2b;
    }

}
