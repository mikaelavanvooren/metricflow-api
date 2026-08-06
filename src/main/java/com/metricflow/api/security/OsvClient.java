package com.metricflow.api.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Queries the OSV.dev database for advisories affecting a set of Maven artifacts.
 *
 * <p>The batch endpoint returns advisory ids only, so each distinct id is then fetched once and
 * cached. Advisory documents are effectively immutable between edits, and the batch response
 * carries a {@code modified} timestamp, so the cache is keyed on id and timestamp together.
 */
public class OsvClient implements AdvisorySource {

    private static final Logger log = LoggerFactory.getLogger(OsvClient.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final int MAX_BATCH_SIZE = 100;

    private final RestTemplate restTemplate;
    private final String baseUrl;
    private final int fetchConcurrency;
    private final Map<String, Vulnerability> cache = new ConcurrentHashMap<>();

    public OsvClient(RestTemplate restTemplate, String baseUrl, int fetchConcurrency) {
        this.restTemplate = restTemplate;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.fetchConcurrency = Math.max(1, fetchConcurrency);
    }

    /**
     * @return advisories per dependency, omitting dependencies with no matches. Never throws for
     *         individual lookup failures; a dependency whose advisories could not be retrieved is
     *         omitted and logged, so one bad response cannot fail the whole scan.
     */
    @Override
    public Map<DependencyCoordinate, List<Vulnerability>> findVulnerabilities(
            List<DependencyCoordinate> dependencies) {

        if (dependencies == null || dependencies.isEmpty()) {
            return Collections.emptyMap();
        }

        Map<DependencyCoordinate, List<String>> idsPerDependency = new LinkedHashMap<>();
        for (int start = 0; start < dependencies.size(); start += MAX_BATCH_SIZE) {
            List<DependencyCoordinate> chunk =
                    dependencies.subList(start, Math.min(start + MAX_BATCH_SIZE, dependencies.size()));
            idsPerDependency.putAll(queryBatch(chunk));
        }

        LinkedHashSet<String> uniqueIds = new LinkedHashSet<>();
        idsPerDependency.values().forEach(uniqueIds::addAll);
        Map<String, Vulnerability> byId = fetchAll(uniqueIds, idsPerDependency);

        Map<DependencyCoordinate, List<Vulnerability>> result = new LinkedHashMap<>();
        idsPerDependency.forEach((dependency, ids) -> {
            List<Vulnerability> found = new ArrayList<>();
            for (String id : ids) {
                Vulnerability vulnerability = byId.get(cacheKey(id, dependency));
                if (vulnerability != null) {
                    found.add(vulnerability);
                }
            }
            if (!found.isEmpty()) {
                result.put(dependency, found);
            }
        });
        return result;
    }

    private Map<DependencyCoordinate, List<String>> queryBatch(List<DependencyCoordinate> chunk) {
        ObjectNode request = MAPPER.createObjectNode();
        ArrayNode queries = request.putArray("queries");
        for (DependencyCoordinate dependency : chunk) {
            ObjectNode query = queries.addObject();
            query.put("version", dependency.getVersion());
            ObjectNode pkg = query.putObject("package");
            pkg.put("name", dependency.getMavenName());
            pkg.put("ecosystem", "Maven");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<DependencyCoordinate, List<String>> perDependency = new LinkedHashMap<>();
        try {
            JsonNode response = restTemplate.postForObject(
                    baseUrl + "/v1/querybatch",
                    new HttpEntity<>(MAPPER.writeValueAsString(request), headers),
                    JsonNode.class);
            List<List<String>> ids = OsvResponseParser.parseBatchIds(response, chunk.size());
            for (int i = 0; i < chunk.size(); i++) {
                if (!ids.get(i).isEmpty()) {
                    perDependency.put(chunk.get(i), ids.get(i));
                }
            }
        } catch (RestClientException | JacksonException e) {
            throw new OsvUnavailableException("OSV batch query failed: " + e.getMessage(), e);
        }
        return perDependency;
    }

    private Map<String, Vulnerability> fetchAll(LinkedHashSet<String> ids,
                                                Map<DependencyCoordinate, List<String>> idsPerDependency) {
        // The same advisory can affect several artifacts, and fix versions are package specific, so
        // each (advisory, package) pair is resolved separately.
        LinkedHashSet<String> work = new LinkedHashSet<>();
        Map<String, String> packageForKey = new LinkedHashMap<>();
        Map<String, String> idForKey = new LinkedHashMap<>();
        idsPerDependency.forEach((dependency, advisoryIds) -> {
            for (String id : advisoryIds) {
                String key = cacheKey(id, dependency);
                work.add(key);
                packageForKey.put(key, dependency.getMavenName());
                idForKey.put(key, id);
            }
        });

        Map<String, Vulnerability> resolved = new ConcurrentHashMap<>();
        List<String> pending = new ArrayList<>();
        for (String key : work) {
            Vulnerability cached = cache.get(key);
            if (cached != null) {
                resolved.put(key, cached);
            } else {
                pending.add(key);
            }
        }
        if (pending.isEmpty()) {
            return resolved;
        }

        ExecutorService pool = Executors.newFixedThreadPool(Math.min(fetchConcurrency, pending.size()));
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (String key : pending) {
                futures.add(pool.submit(() -> {
                    fetchOne(idForKey.get(key), packageForKey.get(key)).ifPresent(vulnerability -> {
                        cache.put(key, vulnerability);
                        resolved.put(key, vulnerability);
                    });
                }));
            }
            for (Future<?> future : futures) {
                try {
                    future.get();
                } catch (ExecutionException e) {
                    log.warn("OSV advisory lookup failed", e.getCause());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        } finally {
            pool.shutdownNow();
        }
        return resolved;
    }

    private Optional<Vulnerability> fetchOne(String id, String packageName) {
        try {
            JsonNode document = restTemplate.getForObject(baseUrl + "/v1/vulns/" + id, JsonNode.class);
            return OsvResponseParser.parseVulnerability(document, packageName);
        } catch (RestClientException e) {
            log.warn("Could not fetch OSV advisory {}: {}", id, e.getMessage());
            return Optional.empty();
        }
    }

    private static String cacheKey(String id, DependencyCoordinate dependency) {
        return id + "|" + dependency.getMavenName();
    }

    /** Raised when OSV itself cannot be reached, which is distinct from finding no advisories. */
    public static class OsvUnavailableException extends RuntimeException {
        public OsvUnavailableException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
