package com.metricflow.api.security;

/**
 * Severity bands, declared in ascending order so ordinal comparison is meaningful.
 */
public enum Severity {

    UNKNOWN,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    /**
     * Maps an advisory's own severity label. GitHub advisories, which supply most Maven data in
     * OSV, use MODERATE where CVSS uses MEDIUM.
     */
    public static Severity fromLabel(String label) {
        if (label == null) {
            return UNKNOWN;
        }
        String normalised = label.trim().toUpperCase();
        switch (normalised) {
            case "CRITICAL":
                return CRITICAL;
            case "HIGH":
                return HIGH;
            case "MODERATE":
            case "MEDIUM":
                return MEDIUM;
            case "LOW":
                return LOW;
            default:
                return UNKNOWN;
        }
    }

    /** CVSS v3 qualitative severity bands. */
    public static Severity fromScore(double score) {
        if (score >= 9.0) {
            return CRITICAL;
        }
        if (score >= 7.0) {
            return HIGH;
        }
        if (score >= 4.0) {
            return MEDIUM;
        }
        if (score > 0.0) {
            return LOW;
        }
        return UNKNOWN;
    }

    /**
     * @return true when this band is at least as severe as {@code threshold}. UNKNOWN only ever
     *         satisfies an UNKNOWN threshold, so filtering never silently hides unrated findings
     *         behind a LOW threshold.
     */
    public boolean atLeast(Severity threshold) {
        if (threshold == null || threshold == UNKNOWN) {
            return true;
        }
        return this != UNKNOWN && ordinal() >= threshold.ordinal();
    }

    public Severity max(Severity other) {
        if (other == null) {
            return this;
        }
        return other.ordinal() > ordinal() ? other : this;
    }
}
