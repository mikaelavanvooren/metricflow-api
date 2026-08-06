package com.metricflow.api.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The result of one scan: advisories affecting resolved dependencies, plus the configuration
 * checks. Serialised outwards only; {@link ScanSnapshot} is the persisted form.
 */
public final class SecurityScanReport {

    private final String scanId;
    private final String scannedAt;
    private final String source;
    private final int dependenciesScanned;
    private final List<VulnerableDependency> dependencyFindings;
    private final List<ConfigFinding> configFindings;
    private final Map<Severity, Integer> countsBySeverity;

    public SecurityScanReport(String scanId,
                              String scannedAt,
                              String source,
                              int dependenciesScanned,
                              List<VulnerableDependency> dependencyFindings,
                              List<ConfigFinding> configFindings) {
        this.scanId = Objects.requireNonNull(scanId, "scanId");
        this.scannedAt = Objects.requireNonNull(scannedAt, "scannedAt");
        this.source = source;
        this.dependenciesScanned = dependenciesScanned;

        List<VulnerableDependency> deps = dependencyFindings == null
                ? new ArrayList<>() : new ArrayList<>(dependencyFindings);
        deps.sort((left, right) -> {
            int bySeverity = Integer.compare(
                    right.getHighestSeverity().ordinal(), left.getHighestSeverity().ordinal());
            return bySeverity != 0 ? bySeverity
                    : left.getDependency().compareTo(right.getDependency());
        });
        this.dependencyFindings = Collections.unmodifiableList(deps);
        this.configFindings = Collections.unmodifiableList(configFindings == null
                ? new ArrayList<>() : new ArrayList<>(configFindings));
        this.countsBySeverity = countBySeverity(this.dependencyFindings, this.configFindings);
    }

    /**
     * Counts every advisory and every failing configuration check by band. Passing checks are
     * deliberately excluded so the totals describe outstanding risk.
     */
    static Map<Severity, Integer> countBySeverity(List<VulnerableDependency> dependencies,
                                                  List<ConfigFinding> configFindings) {
        Map<Severity, Integer> counts = new EnumMap<>(Severity.class);
        for (Severity severity : Severity.values()) {
            counts.put(severity, 0);
        }
        for (VulnerableDependency dependency : dependencies) {
            for (Vulnerability vulnerability : dependency.getVulnerabilities()) {
                counts.merge(vulnerability.getSeverity(), 1, Integer::sum);
            }
        }
        for (ConfigFinding finding : configFindings) {
            if (!finding.isPassing()) {
                counts.merge(finding.getSeverity(), 1, Integer::sum);
            }
        }
        return Collections.unmodifiableMap(counts);
    }

    public String getScanId() {
        return scanId;
    }

    public String getScannedAt() {
        return scannedAt;
    }

    public String getSource() {
        return source;
    }

    public int getDependenciesScanned() {
        return dependenciesScanned;
    }

    public int getVulnerableDependencies() {
        return dependencyFindings.size();
    }

    public int getTotalVulnerabilities() {
        int total = 0;
        for (VulnerableDependency dependency : dependencyFindings) {
            total += dependency.getVulnerabilityCount();
        }
        return total;
    }

    public int getFailingConfigChecks() {
        int total = 0;
        for (ConfigFinding finding : configFindings) {
            if (!finding.isPassing()) {
                total++;
            }
        }
        return total;
    }

    /** Advisories plus failing configuration checks. */
    public int getTotalFindings() {
        return getTotalVulnerabilities() + getFailingConfigChecks();
    }

    public Severity getHighestSeverity() {
        Severity highest = Severity.UNKNOWN;
        for (VulnerableDependency dependency : dependencyFindings) {
            highest = highest.max(dependency.getHighestSeverity());
        }
        for (ConfigFinding finding : configFindings) {
            if (!finding.isPassing()) {
                highest = highest.max(finding.getSeverity());
            }
        }
        return highest;
    }

    public Map<Severity, Integer> getCountsBySeverity() {
        return countsBySeverity;
    }

    public List<VulnerableDependency> getDependencyFindings() {
        return dependencyFindings;
    }

    public List<ConfigFinding> getConfigFindings() {
        return configFindings;
    }

    /**
     * Narrows the report to advisories and failing checks at or above {@code threshold}. Passing
     * checks are always retained so the dashboard can still show them as green.
     */
    public SecurityScanReport filtered(Severity threshold) {
        if (threshold == null || threshold == Severity.UNKNOWN) {
            return this;
        }
        List<VulnerableDependency> deps = new ArrayList<>();
        for (VulnerableDependency dependency : dependencyFindings) {
            VulnerableDependency retained = dependency.filtered(threshold);
            if (retained.getVulnerabilityCount() > 0) {
                deps.add(retained);
            }
        }
        List<ConfigFinding> checks = new ArrayList<>();
        for (ConfigFinding finding : configFindings) {
            if (finding.isPassing() || finding.getSeverity().atLeast(threshold)) {
                checks.add(finding);
            }
        }
        return new SecurityScanReport(scanId, scannedAt, source, dependenciesScanned, deps, checks);
    }
}
