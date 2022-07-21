package de.invesdwin.context.security.crypto.key.password.argon2.jvm.parallel.base;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import javax.annotation.concurrent.ThreadSafe;

import com.password4j.BadParametersException;
import com.password4j.SaltGenerator;
import com.password4j.types.Argon2;

import de.invesdwin.util.concurrent.Executors;
import de.invesdwin.util.lang.Objects;
import de.invesdwin.util.lang.Strings;

/**
 * Adapted from: com.password4j.Argon2Function
 */
//CHECKSTYLE:OFF
@ThreadSafe
public class FastArgon2Function {
    public static final int ARGON2_VERSION_10 = 0x10;

    public static final int ARGON2_VERSION_13 = 0x13;

    public static final int ARGON2_INITIAL_DIGEST_LENGTH = 64;

    public static final int ARGON2_ADDRESSES_IN_BLOCK = 128;

    private static final ConcurrentMap<String, FastArgon2Function> INSTANCES = new ConcurrentHashMap<>();

    private static final int ARGON2_SYNC_POINTS = 4;

    private static final int ARGON2_INITIAL_SEED_LENGTH = 72;

    private static final int ARGON2_BLOCK_SIZE = 1024;

    public static final int ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8;

    private static final ExecutorService EXECUTOR = Executors
            .newFixedThreadPool(FastArgon2Function.class.getSimpleName(), Executors.getCpuThreadPoolCount());
    private final ReusableArgon2DataObjectPool dataPool;

    private final int iterations;

    private final int memory;

    private final int parallelism;

    private final int segmentLength;

    private final Argon2 variant;

    private final int version;

    private final int laneLength;

    public FastArgon2Function(final int memory, final int iterations, final int parallelism, final Argon2 variant,
            final int version) {
        this.variant = variant;
        this.iterations = iterations;
        this.memory = memory;
        this.parallelism = parallelism;
        this.version = version;

        int memoryBlocks = this.memory;

        if (this.memory < 2 * ARGON2_SYNC_POINTS * parallelism) {
            memoryBlocks = 2 * ARGON2_SYNC_POINTS * parallelism;
        }

        segmentLength = memoryBlocks / (parallelism * ARGON2_SYNC_POINTS);
        this.laneLength = segmentLength * ARGON2_SYNC_POINTS;

        memoryBlocks = segmentLength * (parallelism * ARGON2_SYNC_POINTS);

        dataPool = new ReusableArgon2DataObjectPool(parallelism, memoryBlocks);
    }

    /**
     * Creates a singleton instance, depending on the provided memory (KiB), number of iterations, parallelism, length
     * og the output and type.
     *
     * @param memory
     *            memory (KiB)
     * @param iterations
     *            number of iterations
     * @param parallelism
     *            level of parallelism
     * @param outputLength
     *            length of the final hash
     * @param type
     *            argon2 type (i, d or id)
     * @return a singleton instance
     * @since 1.5.0
     */
    public static FastArgon2Function getInstance(final int memory, final int iterations, final int parallelism,
            final Argon2 type) {
        return getInstance(memory, iterations, parallelism, type, ARGON2_VERSION_13);
    }

    /**
     * Creates a singleton instance, depending on the provided logarithmic memory, number of iterations, parallelism,
     * lenght og the output, type and version.
     *
     * @param memory
     *            logarithmic memory
     * @param iterations
     *            number of iterations
     * @param parallelism
     *            level of parallelism
     * @param type
     *            argon2 type (i, d or id)
     * @param version
     *            version of the algorithm (16 or 19)
     * @return a singleton instance
     * @since 1.5.0
     */
    public static FastArgon2Function getInstance(final int memory, final int iterations, final int parallelism,
            final Argon2 type, final int version) {
        final String key = getUID(memory, iterations, parallelism, type, version);
        if (INSTANCES.containsKey(key)) {
            return INSTANCES.get(key);
        } else {
            final FastArgon2Function function = new FastArgon2Function(memory, iterations, parallelism, type, version);
            INSTANCES.put(key, function);
            return function;
        }
    }

    /**
     * Reads the configuration contained in the given hash and builds a singleton instance based on these
     * configurations.
     *
     * @param hashed
     *            an already hashed password
     * @return a singleton instance based on the given hash
     * @since 1.5.0
     */
    public static FastArgon2FunctionFromHash getInstanceFromHash(final String hashed) {
        final Object[] params = decodeHash(hashed);
        final Argon2 type = Argon2.valueOf(((String) params[0]).toUpperCase());
        final int version = (int) params[1];
        final int memory = (int) params[2];
        final int iterations = (int) params[3];
        final int parallelism = (int) params[4];
        final int outputLength = ((byte[]) params[6]).length;
        final FastArgon2Function instance = getInstance(memory, iterations, parallelism, type, version);
        return new FastArgon2FunctionFromHash(instance, outputLength);
    }

    protected static String getUID(final int memory, final int iterations, final int parallelism, final Argon2 type,
            final int version) {
        return memory + "|" + iterations + "|" + parallelism + "|" + type.ordinal() + "|" + version;
    }

    private static byte[] getInitialHashLong(final byte[] initialHash, final byte[] appendix) {
        final byte[] initialHashLong = new byte[ARGON2_INITIAL_SEED_LENGTH];

        System.arraycopy(initialHash, 0, initialHashLong, 0, ARGON2_INITIAL_DIGEST_LENGTH);
        System.arraycopy(appendix, 0, initialHashLong, ARGON2_INITIAL_DIGEST_LENGTH, 4);

        return initialHashLong;
    }

    private static void updateWithLength(final Blake2b blake2b, final byte[] input) {
        if (input != null) {
            blake2b.update(Utils.intToLittleEndianBytes(input.length));
            blake2b.update(input);
        } else {
            blake2b.update(Utils.intToLittleEndianBytes(0));
        }
    }

    private static int getStartingIndex(final int pass, final int slice) {
        if ((pass == 0) && (slice == 0)) {
            return 2;
        } else {
            return 0;
        }
    }

    private static void nextAddresses(final long[] zeroBlock, final long[] inputBlock, final long[] addressBlock) {
        inputBlock[6]++;
        fillBlock(zeroBlock, inputBlock, addressBlock, false);
        fillBlock(zeroBlock, addressBlock, addressBlock, false);
    }

    private static void fillBlock(final long[] x, final long[] y, final long[] currentBlock, final boolean withXor) {

        final long[] r = new long[ARGON2_QWORDS_IN_BLOCK];
        final long[] z = new long[ARGON2_QWORDS_IN_BLOCK];

        Utils.xor(r, x, y);
        System.arraycopy(r, 0, z, 0, z.length);

        for (int i = 0; i < 8; i++) {

            roundFunction(z, 16 * i, 16 * i + 1, 16 * i + 2, 16 * i + 3, 16 * i + 4, 16 * i + 5, 16 * i + 6, 16 * i + 7,
                    16 * i + 8, 16 * i + 9, 16 * i + 10, 16 * i + 11, 16 * i + 12, 16 * i + 13, 16 * i + 14,
                    16 * i + 15);
        }

        for (int i = 0; i < 8; i++) {

            roundFunction(z, 2 * i, 2 * i + 1, 2 * i + 16, 2 * i + 17, 2 * i + 32, 2 * i + 33, 2 * i + 48, 2 * i + 49,
                    2 * i + 64, 2 * i + 65, 2 * i + 80, 2 * i + 81, 2 * i + 96, 2 * i + 97, 2 * i + 112, 2 * i + 113);

        }

        if (withXor) {
            Utils.xor(currentBlock, r, z, currentBlock);
        } else {
            Utils.xor(currentBlock, r, z);
        }
    }

    private static void roundFunction(final long[] block, final int v0, final int v1, final int v2, final int v3,
            final int v4, final int v5, final int v6, final int v7, final int v8, final int v9, // NOSONAR
            final int v10, final int v11, final int v12, final int v13, final int v14, final int v15) {
        f(block, v0, v4, v8, v12);
        f(block, v1, v5, v9, v13);
        f(block, v2, v6, v10, v14);
        f(block, v3, v7, v11, v15);

        f(block, v0, v5, v10, v15);
        f(block, v1, v6, v11, v12);
        f(block, v2, v7, v8, v13);
        f(block, v3, v4, v9, v14);
    }

    private static void f(final long[] block, final int a, final int b, final int c, final int d) {
        fBlaMka(block, a, b);
        rotr64(block, d, a, 32);

        fBlaMka(block, c, d);
        rotr64(block, b, c, 24);

        fBlaMka(block, a, b);
        rotr64(block, d, a, 16);

        fBlaMka(block, c, d);
        rotr64(block, b, c, 63);
    }

    private static void fBlaMka(final long[] block, final int x, final int y) {
        final long m = 0xFFFFFFFFL;
        final long xy = (block[x] & m) * (block[y] & m);

        block[x] = block[x] + block[y] + 2 * xy;
    }

    private static void rotr64(final long[] block, final int v, final int w, final long c) {
        final long temp = block[v] ^ block[w];
        block[v] = (temp >>> c) | (temp << (64 - c));
    }

    private static Object[] decodeHash(final String hash) {
        final Object[] result = new Object[7];
        final String[] parts = hash.split("\\$");
        if (parts.length == 6) {
            result[0] = Strings.removeStart(parts[1], "argon2");
            final String[] params = parts[3].split(",");
            result[1] = Integer.parseInt(Strings.removeStart(parts[2], "v="));
            result[2] = Integer.parseInt(Strings.removeStart(params[0], "m="));
            result[3] = Integer.parseInt(Strings.removeStart(params[1], "t="));
            result[4] = Integer.parseInt(Strings.removeStart(params[2], "p="));
            result[5] = Utils.decodeBase64(parts[4]);
            result[6] = Utils.decodeBase64(parts[5]);
            return result;
        } else {
            throw new BadParametersException("Invalid hashed value");
        }

    }

    protected static String toString(final int memory, final int iterations, final int parallelism, final Argon2 type,
            final int version) {
        return "m=" + memory + ", i=" + iterations + ", p=" + parallelism + ", t=" + type.name() + ", v=" + version;
    }

    public String encodedHash(final byte[] password, byte[] salt, final byte[] pepper, final int outputLength) {
        final ReusableArgon2Data data = dataPool.borrowObject();
        try {
            if (salt == null) {
                salt = SaltGenerator.generate();
            }
            initialize(password, salt, pepper, null, data, outputLength);
            fillMemoryBlocks(data);
            final byte[] hash = ending(data, outputLength);
            return encodeHash(hash, salt);
        } finally {
            dataPool.returnObject(data);
        }
    }

    public byte[] rawHash(final byte[] password, final byte[] salt, final byte[] pepper, final int outputLength) {
        final ReusableArgon2Data data = dataPool.borrowObject();

        try {
            initialize(password, salt, pepper, null, data, outputLength);
            fillMemoryBlocks(data);
            final byte[] hash = ending(data, outputLength);
            return hash;
        } finally {
            dataPool.returnObject(data);
        }
    }

    /**
     * @return the memory in bytes
     * @since 1.5.2
     */
    public int getMemory() {
        return memory;
    }

    /**
     * @return the number of iterations
     * @since 1.5.2
     */
    public int getIterations() {
        return iterations;
    }

    /**
     * @return the degree of parallelism
     * @since 1.5.2
     */
    public int getParallelism() {
        return parallelism;
    }

    /**
     * @return the Argon2 variant (i, d, id)
     * @since 1.5.2
     */
    public Argon2 getVariant() {
        return variant;
    }

    /**
     * @return the version of the algorithm
     * @since 1.5.2
     */
    public int getVersion() {
        return version;
    }

    private void initialize(final byte[] plainTextPassword, final byte[] salt, final byte[] secret,
            final byte[] additional, final ReusableArgon2Data data, final int outputLength) {
        final Blake2b blake2b = data.getBlake2b();
        blake2b.init(FastArgon2Function.ARGON2_INITIAL_DIGEST_LENGTH);

        blake2b.update(Utils.intToLittleEndianBytes(parallelism));
        blake2b.update(Utils.intToLittleEndianBytes(outputLength));
        blake2b.update(Utils.intToLittleEndianBytes(memory));
        blake2b.update(Utils.intToLittleEndianBytes(iterations));
        blake2b.update(Utils.intToLittleEndianBytes(version));
        blake2b.update(Utils.intToLittleEndianBytes(variant.ordinal()));

        updateWithLength(blake2b, plainTextPassword);

        updateWithLength(blake2b, salt);

        updateWithLength(blake2b, secret);

        updateWithLength(blake2b, additional);

        final byte[] initialHash = new byte[64];
        blake2b.doFinal(initialHash, 0);

        final byte[] zeroBytes = { 0, 0, 0, 0 };
        final byte[] oneBytes = { 1, 0, 0, 0 };

        final byte[] initialHashWithZeros = getInitialHashLong(initialHash, zeroBytes);
        final byte[] initialHashWithOnes = getInitialHashLong(initialHash, oneBytes);

        final long[][] blockMemory = data.getBlockMemory();
        for (int i = 0; i < parallelism; i++) {

            final byte[] iBytes = Utils.intToLittleEndianBytes(i);

            System.arraycopy(iBytes, 0, initialHashWithZeros, ARGON2_INITIAL_DIGEST_LENGTH + 4, 4);
            System.arraycopy(iBytes, 0, initialHashWithOnes, ARGON2_INITIAL_DIGEST_LENGTH + 4, 4);

            byte[] blockHashBytes = blake2bLong(blake2b, initialHashWithZeros, ARGON2_BLOCK_SIZE);
            blockMemory[i * laneLength] = Utils.fromBytesToLongs(blockHashBytes);

            blockHashBytes = blake2bLong(initialHashWithOnes, ARGON2_BLOCK_SIZE);
            blockMemory[i * laneLength + 1] = Utils.fromBytesToLongs(blockHashBytes);
        }

    }

    private byte[] blake2bLong(final Blake2b blake2b, final byte[] input, final int outputLength) {

        byte[] result = new byte[outputLength];
        final byte[] outlenBytes = Utils.intToLittleEndianBytes(outputLength);

        final int blake2bLength = 64;

        if (outputLength <= blake2bLength) {
            result = simpleBlake2b(blake2b, input, outlenBytes, outputLength);
        } else {
            byte[] outBuffer;

            outBuffer = simpleBlake2b(blake2b, input, outlenBytes, blake2bLength);
            System.arraycopy(outBuffer, 0, result, 0, blake2bLength / 2);

            final int r = (outputLength / 32) + (outputLength % 32 == 0 ? 0 : 1) - 2;

            int position = blake2bLength / 2;
            for (int i = 2; i <= r; i++, position += blake2bLength / 2) {

                outBuffer = simpleBlake2b(blake2b, outBuffer, null, blake2bLength);
                System.arraycopy(outBuffer, 0, result, position, blake2bLength / 2);
            }

            final int lastLength = outputLength - 32 * r;

            outBuffer = simpleBlake2b(blake2b, outBuffer, null, lastLength);
            System.arraycopy(outBuffer, 0, result, position, lastLength);
        }

        return result;
    }

    private byte[] simpleBlake2b(final Blake2b blake2b, final byte[] input, final byte[] outlenBytes,
            final int outputLength) {
        blake2b.init(outputLength);

        if (outlenBytes != null) {
            blake2b.update(outlenBytes);
        }
        blake2b.update(input);

        final byte[] buff = new byte[outputLength];
        blake2b.doFinal(buff, 0);
        return buff;
    }

    private void fillMemoryBlocks(final ReusableArgon2Data data) {
        if (parallelism == 1) {
            fillMemoryBlockSingleThreaded(data);
        } else {
            fillMemoryBlockMultiThreaded(data);
        }
    }

    private void fillMemoryBlockSingleThreaded(final ReusableArgon2Data data) {
        final long[][] blockMemory = data.getBlockMemory();
        for (int pass = 0; pass < iterations; pass++) {
            for (int slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
                fillSegment(pass, 0, slice, blockMemory);
            }
        }
    }

    private void fillMemoryBlockMultiThreaded(final ReusableArgon2Data data) {
        final long[][] blockMemory = data.getBlockMemory();
        final Future<?>[] futures = data.getFutures();

        for (int i = 0; i < iterations; i++) {
            for (int j = 0; j < ARGON2_SYNC_POINTS; j++) {
                for (int k = 0; k < parallelism; k++) {
                    final int pass = i;
                    final int lane = k;
                    final int slice = j;

                    final Future<?> future = EXECUTOR.submit(() -> fillSegment(pass, lane, slice, blockMemory));

                    futures[k] = future;
                }

                try {
                    for (int k = 0; k < parallelism; k++) {
                        futures[k].get();
                    }
                } catch (InterruptedException | ExecutionException e) {
                    //finally block on the outside clears data
                    Thread.currentThread().interrupt();
                }
            }
        }
    }

    private void fillSegment(final int pass, final int lane, final int slice, final long[][] blockMemory) {

        long[] addressBlock = null;
        long[] inputBlock = null;
        long[] zeroBlock = null;

        final boolean dataIndependentAddressing = isDataIndependentAddressing(pass, slice);
        final int startingIndex = getStartingIndex(pass, slice);
        int currentOffset = lane * laneLength + slice * segmentLength + startingIndex;
        int prevOffset = getPrevOffset(currentOffset);

        if (dataIndependentAddressing) {
            addressBlock = new long[ARGON2_QWORDS_IN_BLOCK];
            zeroBlock = new long[ARGON2_QWORDS_IN_BLOCK];
            inputBlock = new long[ARGON2_QWORDS_IN_BLOCK];

            initAddressBlocks(pass, lane, slice, zeroBlock, inputBlock, addressBlock, blockMemory);
        }

        for (int i = startingIndex; i < segmentLength; i++, currentOffset++, prevOffset++) {
            prevOffset = rotatePrevOffset(currentOffset, prevOffset);

            final long pseudoRandom = getPseudoRandom(i, addressBlock, inputBlock, zeroBlock, prevOffset,
                    dataIndependentAddressing, blockMemory);
            final int refLane = getRefLane(pass, lane, slice, pseudoRandom);
            final int refColumn = getRefColumn(pass, slice, i, pseudoRandom, refLane == lane);

            final long[] prevBlock = blockMemory[prevOffset];
            final long[] refBlock = blockMemory[((laneLength) * refLane + refColumn)];
            final long[] currentBlock = blockMemory[currentOffset];

            final boolean withXor = isWithXor(pass);
            fillBlock(prevBlock, refBlock, currentBlock, withXor);
        }
    }

    private boolean isDataIndependentAddressing(final int pass, final int slice) {
        return (variant == Argon2.I) || (variant == Argon2.ID && (pass == 0) && (slice < ARGON2_SYNC_POINTS / 2));
    }

    private int getPrevOffset(final int currentOffset) {
        if (currentOffset % laneLength == 0) {

            return currentOffset + laneLength - 1;
        } else {

            return currentOffset - 1;
        }
    }

    private int rotatePrevOffset(final int currentOffset, int prevOffset) {
        if (currentOffset % laneLength == 1) {
            prevOffset = currentOffset - 1;
        }
        return prevOffset;
    }

    private long getPseudoRandom(final int index, final long[] addressBlock, final long[] inputBlock,
            final long[] zeroBlock, final int prevOffset, final boolean dataIndependentAddressing,
            final long[][] blockMemory) {
        if (dataIndependentAddressing) {
            if (index % ARGON2_ADDRESSES_IN_BLOCK == 0) {
                nextAddresses(zeroBlock, inputBlock, addressBlock);
            }
            return addressBlock[index % ARGON2_ADDRESSES_IN_BLOCK];
        } else {
            return blockMemory[prevOffset][0];
        }
    }

    private int getRefLane(final int pass, final int lane, final int slice, final long pseudoRandom) {
        int refLane = (int) ((pseudoRandom >>> 32) % parallelism);

        if (pass == 0 && slice == 0) {
            refLane = lane;
        }
        return refLane;
    }

    private void initAddressBlocks(final int pass, final int lane, final int slice, final long[] zeroBlock,
            final long[] inputBlock, final long[] addressBlock, final long[][] blockMemory) {
        inputBlock[0] = Utils.intToLong(pass);
        inputBlock[1] = Utils.intToLong(lane);
        inputBlock[2] = Utils.intToLong(slice);
        inputBlock[3] = Utils.intToLong(blockMemory.length);
        inputBlock[4] = Utils.intToLong(iterations);
        inputBlock[5] = Utils.intToLong(variant.ordinal());

        if (pass == 0 && slice == 0) {

            nextAddresses(zeroBlock, inputBlock, addressBlock);
        }
    }

    private int getRefColumn(final int pass, final int slice, final int index, final long pseudoRandom,
            final boolean sameLane) {

        int referenceAreaSize;
        int startPosition;

        if (pass == 0) {
            startPosition = 0;

            if (sameLane) {
                referenceAreaSize = slice * segmentLength + index - 1;
            } else {
                referenceAreaSize = slice * segmentLength + ((index == 0) ? (-1) : 0);
            }

        } else {
            startPosition = ((slice + 1) * segmentLength) % laneLength;

            if (sameLane) {
                referenceAreaSize = laneLength - segmentLength + index - 1;
            } else {
                referenceAreaSize = laneLength - segmentLength + ((index == 0) ? (-1) : 0);
            }
        }

        long relativePosition = pseudoRandom & 0xFFFFFFFFL;

        relativePosition = (relativePosition * relativePosition) >>> 32;
        relativePosition = referenceAreaSize - 1 - (referenceAreaSize * relativePosition >>> 32);

        return (int) (startPosition + relativePosition) % laneLength;
    }

    private boolean isWithXor(final int pass) {
        return !(pass == 0 || version == ARGON2_VERSION_10);
    }

    private byte[] ending(final ReusableArgon2Data data, final int outputLength) {
        final long[][] blockMemory = data.getBlockMemory();

        final long[] finalBlock = blockMemory[laneLength - 1];

        for (int i = 1; i < parallelism; i++) {
            final int lastBlockInLane = i * laneLength + (laneLength - 1);
            Utils.xor(finalBlock, blockMemory[lastBlockInLane]);
        }

        final byte[] finalBlockBytes = new byte[ARGON2_BLOCK_SIZE];

        for (int i = 0; i < finalBlock.length; i++) {
            final byte[] bytes = Utils.longToLittleEndianBytes(finalBlock[i]);
            System.arraycopy(bytes, 0, finalBlockBytes, i * bytes.length, bytes.length);
        }

        final byte[] finalResult = blake2bLong(finalBlockBytes, outputLength);

        return finalResult;
    }

    private String encodeHash(final byte[] hash, final byte[] salt) {
        return "$argon2" + variant.name().toLowerCase() + "$v=" + version + "$m=" + memory + ",t=" + iterations + ",p="
                + parallelism + "$" + Utils.encodeBase64(salt, false) + "$" + Utils.encodeBase64(hash, false);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof FastArgon2Function)) {
            return false;
        }
        final FastArgon2Function other = (FastArgon2Function) o;
        return iterations == other.iterations //
                && memory == other.memory //
                && parallelism == other.parallelism //
                && version == other.version //
                && variant == other.variant;
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(iterations, memory, parallelism, variant, version);
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + '[' + toString(memory, iterations, parallelism, variant, version) + ']';
    }
}
