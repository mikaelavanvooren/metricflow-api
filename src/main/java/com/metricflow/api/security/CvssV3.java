package com.metricflow.api.security;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Computes a CVSS v3.x base score from a vector string.
 *
 * <p>OSV records severity as a vector rather than a number, so a score has to be derived locally
 * whenever an advisory carries no qualitative label. Implements the base-score equations from the
 * CVSS v3.1 specification, section 7.1.
 */
public final class CvssV3 {

    private static final Map<String, Double> ATTACK_VECTOR = new HashMap<>();
    private static final Map<String, Double> ATTACK_COMPLEXITY = new HashMap<>();
    private static final Map<String, Double> PRIVILEGES_REQUIRED = new HashMap<>();
    private static final Map<String, Double> PRIVILEGES_REQUIRED_SCOPE_CHANGED = new HashMap<>();
    private static final Map<String, Double> USER_INTERACTION = new HashMap<>();
    private static final Map<String, Double> IMPACT = new HashMap<>();

    static {
        ATTACK_VECTOR.put("N", 0.85);
        ATTACK_VECTOR.put("A", 0.62);
        ATTACK_VECTOR.put("L", 0.55);
        ATTACK_VECTOR.put("P", 0.2);

        ATTACK_COMPLEXITY.put("L", 0.77);
        ATTACK_COMPLEXITY.put("H", 0.44);

        PRIVILEGES_REQUIRED.put("N", 0.85);
        PRIVILEGES_REQUIRED.put("L", 0.62);
        PRIVILEGES_REQUIRED.put("H", 0.27);

        // Privileges Required is weighted differently once Scope changes.
        PRIVILEGES_REQUIRED_SCOPE_CHANGED.put("N", 0.85);
        PRIVILEGES_REQUIRED_SCOPE_CHANGED.put("L", 0.68);
        PRIVILEGES_REQUIRED_SCOPE_CHANGED.put("H", 0.5);

        USER_INTERACTION.put("N", 0.85);
        USER_INTERACTION.put("R", 0.62);

        IMPACT.put("H", 0.56);
        IMPACT.put("L", 0.22);
        IMPACT.put("N", 0.0);
    }

    private CvssV3() {
    }

    /**
     * @return the base score, or empty when the vector is absent, not CVSS v3, or missing any
     *         base metric.
     */
    public static Optional<Double> baseScore(String vector) {
        if (vector == null || vector.trim().isEmpty()) {
            return Optional.empty();
        }
        Map<String, String> metrics = new HashMap<>();
        String[] fields = vector.trim().split("/");
        for (String field : fields) {
            int separator = field.indexOf(':');
            if (separator > 0 && separator < field.length() - 1) {
                metrics.put(field.substring(0, separator).trim().toUpperCase(),
                        field.substring(separator + 1).trim().toUpperCase());
            }
        }

        String version = metrics.get("CVSS");
        if (version == null || !version.startsWith("3")) {
            return Optional.empty();
        }

        boolean scopeChanged = "C".equals(metrics.get("S"));
        Double av = ATTACK_VECTOR.get(metrics.get("AV"));
        Double ac = ATTACK_COMPLEXITY.get(metrics.get("AC"));
        Double pr = (scopeChanged ? PRIVILEGES_REQUIRED_SCOPE_CHANGED : PRIVILEGES_REQUIRED)
                .get(metrics.get("PR"));
        Double ui = USER_INTERACTION.get(metrics.get("UI"));
        Double confidentiality = IMPACT.get(metrics.get("C"));
        Double integrity = IMPACT.get(metrics.get("I"));
        Double availability = IMPACT.get(metrics.get("A"));

        if (av == null || ac == null || pr == null || ui == null
                || confidentiality == null || integrity == null || availability == null) {
            return Optional.empty();
        }

        double impactBase = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability));
        double impact = scopeChanged
                ? 7.52 * (impactBase - 0.029) - 3.25 * Math.pow(impactBase - 0.02, 15)
                : 6.42 * impactBase;
        if (impact <= 0) {
            return Optional.of(0.0);
        }

        double exploitability = 8.22 * av * ac * pr * ui;
        double raw = Math.min(impact + exploitability, 10.0) * (scopeChanged ? 1.08 : 1.0);
        return Optional.of(roundUp(Math.min(raw, 10.0)));
    }

    /**
     * CVSS "Roundup": the smallest number to one decimal place that is >= the input. Implemented on
     * integer arithmetic as the specification requires, because naive rounding of values such as
     * 8.6 - which is not exactly representable - produces off-by-one-tenth scores.
     */
    static double roundUp(double value) {
        long scaled = Math.round(value * 100000);
        if (scaled % 10000 == 0) {
            return scaled / 100000.0;
        }
        return (Math.floor(scaled / 10000.0) + 1) / 10.0;
    }
}
