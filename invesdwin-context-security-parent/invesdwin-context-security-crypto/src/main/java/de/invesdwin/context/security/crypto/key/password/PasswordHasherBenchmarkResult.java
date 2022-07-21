package de.invesdwin.context.security.crypto.key.password;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.util.lang.Objects;
import de.invesdwin.util.time.duration.Duration;

@Immutable
public class PasswordHasherBenchmarkResult<E extends IPasswordHasher> {
    private final E instance;
    private final Duration duration;

    public PasswordHasherBenchmarkResult(final E instance, final Duration duration) {
        this.instance = instance;
        this.duration = duration;
    }

    public E getInstance() {
        return instance;
    }

    public Duration getDuration() {
        return duration;
    }

    @Override
    public String toString() {
        return Objects.toStringHelper(this)
                .add("duration", duration)
                .add("iterations", instance.getIterations())
                .with(instance)
                .toString();
    }

}