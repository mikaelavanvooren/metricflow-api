package com.metricflow.api.security;

import java.util.Objects;

/**
 * A single resolved Maven artifact on the application's own classpath.
 */
public final class DependencyCoordinate implements Comparable<DependencyCoordinate> {

    private final String groupId;
    private final String artifactId;
    private final String version;
    private final String scope;

    public DependencyCoordinate(String groupId, String artifactId, String version, String scope) {
        this.groupId = Objects.requireNonNull(groupId, "groupId");
        this.artifactId = Objects.requireNonNull(artifactId, "artifactId");
        this.version = Objects.requireNonNull(version, "version");
        this.scope = scope == null ? "compile" : scope;
    }

    public String getGroupId() {
        return groupId;
    }

    public String getArtifactId() {
        return artifactId;
    }

    public String getVersion() {
        return version;
    }

    public String getScope() {
        return scope;
    }

    /** The identifier OSV uses for the Maven ecosystem. */
    public String getMavenName() {
        return groupId + ":" + artifactId;
    }

    public String getPurl() {
        return "pkg:maven/" + groupId + "/" + artifactId + "@" + version;
    }

    /** Stable key for correlating the same dependency across two scans. */
    public String getKey() {
        return getMavenName() + "@" + version;
    }

    @Override
    public int compareTo(DependencyCoordinate other) {
        int byName = getMavenName().compareTo(other.getMavenName());
        return byName != 0 ? byName : version.compareTo(other.version);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof DependencyCoordinate)) {
            return false;
        }
        DependencyCoordinate other = (DependencyCoordinate) o;
        return groupId.equals(other.groupId)
                && artifactId.equals(other.artifactId)
                && version.equals(other.version)
                && scope.equals(other.scope);
    }

    @Override
    public int hashCode() {
        return Objects.hash(groupId, artifactId, version, scope);
    }

    @Override
    public String toString() {
        return getMavenName() + ":" + version + ":" + scope;
    }
}
