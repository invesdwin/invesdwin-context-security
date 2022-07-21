package de.invesdwin.context.security.crypto.key.password;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.util.lang.Objects;
import de.invesdwin.util.time.duration.Duration;

@Immutable
public class PasswordHasherBenchmarkResult<E extends IPasswordHasher> {
    private final Duration duration;
    private final E instance;

    public PasswordHasherBenchmarkResult(final Duration duration, final E instance) {
        this.duration = duration;
        this.instance = instance;
    }

    public E getInstance() {
        return instance;
    }

    public Duration getDuration() {
        return duration;
    }

    @Override
    public String toString() {
        return Objects.toStringHelper(this).add("duration", duration).with(instance).toString();
    }

}