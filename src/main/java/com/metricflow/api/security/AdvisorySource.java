package com.metricflow.api.security;

import java.util.List;
import java.util.Map;

/**
 * Looks up published advisories for a set of dependencies.
 */
@FunctionalInterface
public interface AdvisorySource {

    /**
     * @return advisories per dependency, omitting dependencies with no matches
     * @throws OsvClient.OsvUnavailableException when the advisory database cannot be reached, which
     *         must not be conflated with finding nothing
     */
    Map<DependencyCoordinate, List<Vulnerability>> findVulnerabilities(List<DependencyCoordinate> dependencies);
}
