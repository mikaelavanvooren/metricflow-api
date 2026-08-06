package com.metricflow.api.security;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Reads the resolved dependency list that maven-dependency-plugin writes onto the classpath at
 * build time. A JVM cannot enumerate the Maven coordinates of its own classpath, so this file is
 * the only reliable source for what to ask a vulnerability database about.
 */
public final class DependencyInventory implements DependencySource {

    public static final String DEFAULT_RESOURCE = "META-INF/metricflow-dependencies.txt";

    // Maven renders the list with ANSI styling and a trailing " -- module x (auto)" descriptor
    // when it detects a colour-capable terminal, neither of which is part of the coordinate.
    private static final Pattern ANSI = Pattern.compile("\u001B\\[[;\\d]*m");
    private static final Pattern MODULE_SUFFIX = Pattern.compile("\\s+--\\s+module\\s.*$");
    private static final Pattern VALID_SEGMENT = Pattern.compile("[A-Za-z0-9._+\\-]+");

    private final String resourcePath;

    public DependencyInventory() {
        this(DEFAULT_RESOURCE);
    }

    public DependencyInventory(String resourcePath) {
        this.resourcePath = resourcePath;
    }

    /**
     * @return the recorded dependencies, or empty when the build-time inventory is absent, which
     *         happens when the application runs from classes that were not produced by the Maven
     *         build. Callers surface that as "scan unavailable" rather than as an empty scan.
     */
    @Override
    public Optional<List<DependencyCoordinate>> load() {
        Resource resource = new ClassPathResource(resourcePath);
        if (!resource.exists()) {
            return Optional.empty();
        }
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
            List<String> lines = new ArrayList<>();
            String line;
            while ((line = reader.readLine()) != null) {
                lines.add(line);
            }
            return Optional.of(parse(lines));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    /**
     * Parses {@code dependency:list} output. Unrecognised lines, such as the "The following files
     * have been resolved:" header, are skipped rather than treated as errors.
     */
    public static List<DependencyCoordinate> parse(List<String> lines) {
        LinkedHashSet<DependencyCoordinate> found = new LinkedHashSet<>();
        for (String raw : lines) {
            parseLine(raw).ifPresent(found::add);
        }
        List<DependencyCoordinate> sorted = new ArrayList<>(found);
        Collections.sort(sorted);
        return Collections.unmodifiableList(sorted);
    }

    static Optional<DependencyCoordinate> parseLine(String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        String line = MODULE_SUFFIX.matcher(ANSI.matcher(raw).replaceAll("")).replaceAll("").trim();
        if (line.isEmpty() || line.endsWith(":")) {
            return Optional.empty();
        }

        String[] parts = line.split(":");
        String groupId;
        String artifactId;
        String version;
        String scope;
        if (parts.length == 5) {
            // group:artifact:type:version:scope
            groupId = parts[0];
            artifactId = parts[1];
            version = parts[3];
            scope = parts[4];
        } else if (parts.length == 6) {
            // group:artifact:type:classifier:version:scope
            groupId = parts[0];
            artifactId = parts[1];
            version = parts[4];
            scope = parts[5];
        } else {
            return Optional.empty();
        }

        if (!isSegment(groupId) || !isSegment(artifactId) || !isSegment(version) || !isSegment(scope)) {
            return Optional.empty();
        }
        return Optional.of(new DependencyCoordinate(groupId, artifactId, version, scope));
    }

    private static boolean isSegment(String candidate) {
        return candidate != null && !candidate.isEmpty() && VALID_SEGMENT.matcher(candidate).matches();
    }
}
