package de.invesdwin.context.security.crypto.key.password;

import javax.annotation.concurrent.Immutable;

import de.invesdwin.util.lang.Objects;
import de.invesdwin.util.lang.ToStringHelper;
import de.invesdwin.util.lang.string.Strings;
import de.invesdwin.util.time.duration.Duration;

@Immutable
public class PasswordHasherBenchmarkResult<E extends IPasswordHasher> {
    private final Duration duration;
    private final String costName;
    private final int cost;
    private final E instance;

    public PasswordHasherBenchmarkResult(final Duration duration, final String costName, final int cost,
            final E instance) {
        this.duration = duration;
        this.costName = costName;
        this.cost = cost;
        this.instance = instance;
    }

    public E getInstance() {
        return instance;
    }

    public String getCostName() {
        return costName;
    }

    public int getCost() {
        return cost;
    }

    public Duration getDuration() {
        return duration;
    }

    @Override
    public String toString() {
        final ToStringHelper helper = Objects.toStringHelper(this).add("duration", duration);
        if (Strings.isNotBlank(costName)) {
            helper.add(costName, cost);
        }
        return helper.with(instance).toString();
    }

}