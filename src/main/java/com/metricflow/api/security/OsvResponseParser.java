package com.metricflow.api.security;

import tools.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;

/**
 * Pure translation of OSV JSON documents into the model. Kept free of HTTP concerns so the
 * mapping rules can be tested against recorded payloads.
 */
public final class OsvResponseParser {

    private OsvResponseParser() {
    }

    /**
     * Reads the advisory ids from a {@code /v1/querybatch} response. The batch endpoint returns
     * ids only, in the same order as the submitted queries.
     *
     * @return one id list per query, always the same length as {@code queryCount}
     */
    public static List<List<String>> parseBatchIds(JsonNode root, int queryCount) {
        List<List<String>> perQuery = new ArrayList<>();
        JsonNode results = root == null ? null : root.path("results");
        for (int i = 0; i < queryCount; i++) {
            List<String> ids = new ArrayList<>();
            if (results != null && results.isArray() && i < results.size()) {
                for (JsonNode vuln : results.get(i).path("vulns")) {
                    String id = vuln.path("id").asString(null);
                    if (id != null && !id.isEmpty()) {
                        ids.add(id);
                    }
                }
            }
            perQuery.add(Collections.unmodifiableList(ids));
        }
        return Collections.unmodifiableList(perQuery);
    }

    /**
     * Converts a {@code /v1/vulns/{id}} document.
     *
     * @param packageName the Maven {@code group:artifact} that was queried, used to keep fix
     *                    versions from other artifacts in the same advisory out of the result
     */
    public static Optional<Vulnerability> parseVulnerability(JsonNode root, String packageName) {
        if (root == null || root.isMissingNode()) {
            return Optional.empty();
        }
        String id = root.path("id").asString(null);
        if (id == null || id.isEmpty()) {
            return Optional.empty();
        }

        String vector = cvssVector(root);
        Double score = CvssV3.baseScore(vector).orElse(null);

        // An advisory's own label is authoritative where present; a locally computed CVSS score is
        // only a fallback, since not every advisory carries a vector either.
        Severity severity = Severity.fromLabel(root.path("database_specific").path("severity").asString(null));
        if (severity == Severity.UNKNOWN && score != null) {
            severity = Severity.fromScore(score);
        }

        return Optional.of(new Vulnerability(
                id,
                textList(root.path("aliases")),
                severity,
                score,
                vector,
                summary(root),
                fixedVersions(root, packageName),
                references(root),
                root.path("published").asString(null),
                root.path("modified").asString(null)));
    }

    private static String cvssVector(JsonNode root) {
        JsonNode severities = root.path("severity");
        if (!severities.isArray()) {
            return null;
        }
        // Prefer the newest CVSS revision the advisory offers.
        String best = null;
        for (JsonNode entry : severities) {
            String type = entry.path("type").asString("");
            String score = entry.path("score").asString(null);
            if (score == null || score.isEmpty()) {
                continue;
            }
            if ("CVSS_V3".equals(type)) {
                best = score;
            } else if (best == null && type.startsWith("CVSS")) {
                best = score;
            }
        }
        return best;
    }

    private static String summary(JsonNode root) {
        String summary = root.path("summary").asString(null);
        if (summary != null && !summary.trim().isEmpty()) {
            return summary.trim();
        }
        String details = root.path("details").asString(null);
        if (details == null || details.trim().isEmpty()) {
            return null;
        }
        // "details" is long-form markdown; the dashboard only needs a single line of context.
        String firstLine = details.trim().split("\\R", 2)[0].trim();
        return firstLine.length() > 300 ? firstLine.substring(0, 297) + "..." : firstLine;
    }

    private static List<String> fixedVersions(JsonNode root, String packageName) {
        LinkedHashSet<String> fixed = new LinkedHashSet<>();
        for (JsonNode affected : root.path("affected")) {
            String name = affected.path("package").path("name").asString("");
            if (packageName != null && !packageName.isEmpty() && !packageName.equals(name)) {
                continue;
            }
            for (JsonNode range : affected.path("ranges")) {
                for (JsonNode event : range.path("events")) {
                    String version = event.path("fixed").asString(null);
                    if (version != null && !version.isEmpty()) {
                        fixed.add(version);
                    }
                }
            }
        }
        return new ArrayList<>(fixed);
    }

    private static List<String> references(JsonNode root) {
        LinkedHashSet<String> urls = new LinkedHashSet<>();
        for (JsonNode reference : root.path("references")) {
            String url = reference.path("url").asString(null);
            if (url != null && !url.isEmpty()) {
                urls.add(url);
            }
        }
        return new ArrayList<>(urls);
    }

    private static List<String> textList(JsonNode array) {
        List<String> values = new ArrayList<>();
        if (array.isArray()) {
            for (JsonNode entry : array) {
                String text = entry.asString(null);
                if (text != null && !text.isEmpty()) {
                    values.add(text);
                }
            }
        }
        return values;
    }
}
