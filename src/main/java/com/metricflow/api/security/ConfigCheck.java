package com.metricflow.api.security;

/**
 * A single configuration or hygiene rule.
 *
 * <p>Implementations must be pure functions of the supplied context: no I/O, no time, no
 * randomness, so a scan run twice over the same configuration yields the same findings.
 */
public interface ConfigCheck {

    /** Stable identifier, used as the correlation key when diffing two scans. */
    String getId();

    ConfigFinding evaluate(ConfigCheckContext context);
}
