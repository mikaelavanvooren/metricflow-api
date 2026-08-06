package com.metricflow.api.security;

import java.util.List;
import java.util.Optional;

/**
 * Supplies the set of dependencies to scan.
 */
@FunctionalInterface
public interface DependencySource {

    /**
     * @return the resolved dependencies, or empty when they cannot be determined. Empty must be
     *         distinguished from "no dependencies", because reporting an unknown classpath as clean
     *         would hide every finding.
     */
    Optional<List<DependencyCoordinate>> load();
}
