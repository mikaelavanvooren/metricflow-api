package com.metricflow.api.security;

import java.util.Objects;

/**
 * The outcome of one configuration or hygiene check.
 *
 * <p>Passing checks are reported alongside failing ones so that fixing something shows up as a
 * check turning green rather than as a row silently disappearing.
 */
public final class ConfigFinding {

    private final String id;
    private final String title;
    private final Severity severity;
    private final boolean passing;
    private final String detail;
    private final String remediation;

    private ConfigFinding(String id, String title, Severity severity, boolean passing,
                          String detail, String remediation) {
        this.id = Objects.requireNonNull(id, "id");
        this.title = Objects.requireNonNull(title, "title");
        this.severity = severity == null ? Severity.UNKNOWN : severity;
        this.passing = passing;
        this.detail = detail;
        this.remediation = remediation;
    }

    public static ConfigFinding failing(String id, String title, Severity severity,
                                        String detail, String remediation) {
        return new ConfigFinding(id, title, severity, false, detail, remediation);
    }

    public static ConfigFinding passing(String id, String title, String detail) {
        return new ConfigFinding(id, title, Severity.UNKNOWN, true, detail, null);
    }

    public String getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    /** Severity of the risk when failing; UNKNOWN for a passing check. */
    public Severity getSeverity() {
        return severity;
    }

    public boolean isPassing() {
        return passing;
    }

    public String getDetail() {
        return detail;
    }

    public String getRemediation() {
        return remediation;
    }

    @Override
    public String toString() {
        return id + (passing ? " [pass]" : " [fail:" + severity + "]");
    }
}
