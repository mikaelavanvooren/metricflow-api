package com.metricflow.api.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * A dependency together with every advisory that matched its resolved version.
 */
public final class VulnerableDependency {

    private final DependencyCoordinate dependency;
    private final List<Vulnerability> vulnerabilities;
    private final Severity highestSeverity;

    public VulnerableDependency(DependencyCoordinate dependency, List<Vulnerability> vulnerabilities) {
        this.dependency = Objects.requireNonNull(dependency, "dependency");
        List<Vulnerability> copy = vulnerabilities == null ? new ArrayList<>() : new ArrayList<>(vulnerabilities);
        copy.sort((left, right) -> {
            int bySeverity = Integer.compare(right.getSeverity().ordinal(), left.getSeverity().ordinal());
            return bySeverity != 0 ? bySeverity : left.getId().compareTo(right.getId());
        });
        this.vulnerabilities = Collections.unmodifiableList(copy);

        Severity highest = Severity.UNKNOWN;
        for (Vulnerability vulnerability : copy) {
            highest = highest.max(vulnerability.getSeverity());
        }
        this.highestSeverity = highest;
    }

    public DependencyCoordinate getDependency() {
        return dependency;
    }

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public Severity getHighestSeverity() {
        return highestSeverity;
    }

    public int getVulnerabilityCount() {
        return vulnerabilities.size();
    }

    /** Returns a copy retaining only advisories at or above {@code threshold}. */
    public VulnerableDependency filtered(Severity threshold) {
        List<Vulnerability> retained = new ArrayList<>();
        for (Vulnerability vulnerability : vulnerabilities) {
            if (vulnerability.getSeverity().atLeast(threshold)) {
                retained.add(vulnerability);
            }
        }
        return new VulnerableDependency(dependency, retained);
    }

    @Override
    public String toString() {
        return dependency + " -> " + vulnerabilities.size() + " advisories";
    }
}
