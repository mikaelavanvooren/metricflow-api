package com.metricflow.api.security;

import java.util.ArrayList;
import java.util.List;

/**
 * One finding reduced to the fields a diff needs. Mutable with a default constructor because these
 * are read back from disk by Jackson.
 */
public class SnapshotEntry {

    public static final String KIND_DEPENDENCY = "dependency";
    public static final String KIND_CONFIG = "config";

    private String key;
    private String kind;
    private String label;
    private String advisoryId;
    private String severity;
    private List<String> fixedVersions = new ArrayList<>();

    public SnapshotEntry() {
    }

    public static SnapshotEntry forAdvisory(DependencyCoordinate dependency, Vulnerability vulnerability) {
        SnapshotEntry entry = new SnapshotEntry();
        // Version is part of the key on purpose: upgrading a dependency retires the old finding and
        // that is exactly what should show up as fixed.
        entry.key = KIND_DEPENDENCY + ":" + dependency.getKey() + "|" + vulnerability.getId();
        entry.kind = KIND_DEPENDENCY;
        entry.label = dependency.getMavenName() + " " + dependency.getVersion();
        entry.advisoryId = vulnerability.getId();
        entry.severity = vulnerability.getSeverity().name();
        entry.fixedVersions = new ArrayList<>(vulnerability.getFixedVersions());
        return entry;
    }

    public static SnapshotEntry forConfigFinding(ConfigFinding finding) {
        SnapshotEntry entry = new SnapshotEntry();
        entry.key = KIND_CONFIG + ":" + finding.getId();
        entry.kind = KIND_CONFIG;
        entry.label = finding.getTitle();
        entry.severity = finding.getSeverity().name();
        return entry;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getKind() {
        return kind;
    }

    public void setKind(String kind) {
        this.kind = kind;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getAdvisoryId() {
        return advisoryId;
    }

    public void setAdvisoryId(String advisoryId) {
        this.advisoryId = advisoryId;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public List<String> getFixedVersions() {
        return fixedVersions;
    }

    public void setFixedVersions(List<String> fixedVersions) {
        this.fixedVersions = fixedVersions == null ? new ArrayList<>() : new ArrayList<>(fixedVersions);
    }

    @Override
    public String toString() {
        return key;
    }
}
