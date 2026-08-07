package com.metricflow.api.security;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The persisted form of a scan, holding only what history and diffing need.
 *
 * <p>Deliberately a mutable POJO: snapshots are read back from disk, possibly written by an earlier
 * version of the application, so Jackson needs a default constructor and unknown fields must not
 * break deserialisation.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ScanSnapshot {

    private String scanId;
    private String scannedAt;
    private int dependenciesScanned;
    private int vulnerableDependencies;
    private int totalVulnerabilities;
    private int failingConfigChecks;
    private Map<String, Integer> countsBySeverity = new LinkedHashMap<>();
    private List<SnapshotEntry> entries = new ArrayList<>();

    public ScanSnapshot() {
    }

    public static ScanSnapshot from(SecurityScanReport report) {
        ScanSnapshot snapshot = new ScanSnapshot();
        snapshot.scanId = report.getScanId();
        snapshot.scannedAt = report.getScannedAt();
        snapshot.dependenciesScanned = report.getDependenciesScanned();
        snapshot.vulnerableDependencies = report.getVulnerableDependencies();
        snapshot.totalVulnerabilities = report.getTotalVulnerabilities();
        snapshot.failingConfigChecks = report.getFailingConfigChecks();

        Map<String, Integer> counts = new LinkedHashMap<>();
        report.getCountsBySeverity().forEach((severity, count) -> counts.put(severity.name(), count));
        snapshot.countsBySeverity = counts;

        List<SnapshotEntry> entries = new ArrayList<>();
        for (VulnerableDependency dependency : report.getDependencyFindings()) {
            for (Vulnerability vulnerability : dependency.getVulnerabilities()) {
                entries.add(SnapshotEntry.forAdvisory(dependency.getDependency(), vulnerability));
            }
        }
        for (ConfigFinding finding : report.getConfigFindings()) {
            if (!finding.isPassing()) {
                entries.add(SnapshotEntry.forConfigFinding(finding));
            }
        }
        snapshot.entries = entries;
        return snapshot;
    }

    @JsonIgnore
    public int getTotalFindings() {
        return totalVulnerabilities + failingConfigChecks;
    }

    public String getScanId() {
        return scanId;
    }

    public void setScanId(String scanId) {
        this.scanId = scanId;
    }

    public String getScannedAt() {
        return scannedAt;
    }

    public void setScannedAt(String scannedAt) {
        this.scannedAt = scannedAt;
    }

    public int getDependenciesScanned() {
        return dependenciesScanned;
    }

    public void setDependenciesScanned(int dependenciesScanned) {
        this.dependenciesScanned = dependenciesScanned;
    }

    public int getVulnerableDependencies() {
        return vulnerableDependencies;
    }

    public void setVulnerableDependencies(int vulnerableDependencies) {
        this.vulnerableDependencies = vulnerableDependencies;
    }

    public int getTotalVulnerabilities() {
        return totalVulnerabilities;
    }

    public void setTotalVulnerabilities(int totalVulnerabilities) {
        this.totalVulnerabilities = totalVulnerabilities;
    }

    public int getFailingConfigChecks() {
        return failingConfigChecks;
    }

    public void setFailingConfigChecks(int failingConfigChecks) {
        this.failingConfigChecks = failingConfigChecks;
    }

    public Map<String, Integer> getCountsBySeverity() {
        return countsBySeverity;
    }

    public void setCountsBySeverity(Map<String, Integer> countsBySeverity) {
        this.countsBySeverity = countsBySeverity == null ? new LinkedHashMap<>() : countsBySeverity;
    }

    public List<SnapshotEntry> getEntries() {
        return entries;
    }

    public void setEntries(List<SnapshotEntry> entries) {
        this.entries = entries == null ? new ArrayList<>() : entries;
    }
}
