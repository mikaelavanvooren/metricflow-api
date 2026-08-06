package com.metricflow.api.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SeverityTests {

    @Test
    void mapsAdvisoryLabels() {
        assertThat(Severity.fromLabel("CRITICAL")).isEqualTo(Severity.CRITICAL);
        assertThat(Severity.fromLabel("high")).isEqualTo(Severity.HIGH);
        assertThat(Severity.fromLabel("  Low  ")).isEqualTo(Severity.LOW);
    }

    // GitHub advisories, which supply most Maven data in OSV, say MODERATE where CVSS says MEDIUM.
    @Test
    void treatsModerateAsMedium() {
        assertThat(Severity.fromLabel("MODERATE")).isEqualTo(Severity.MEDIUM);
        assertThat(Severity.fromLabel("MEDIUM")).isEqualTo(Severity.MEDIUM);
    }

    @Test
    void mapsUnrecognisedLabelsToUnknown() {
        assertThat(Severity.fromLabel(null)).isEqualTo(Severity.UNKNOWN);
        assertThat(Severity.fromLabel("")).isEqualTo(Severity.UNKNOWN);
        assertThat(Severity.fromLabel("SEVERE")).isEqualTo(Severity.UNKNOWN);
    }

    @Test
    void mapsScoresToCvssBands() {
        assertThat(Severity.fromScore(10.0)).isEqualTo(Severity.CRITICAL);
        assertThat(Severity.fromScore(9.0)).isEqualTo(Severity.CRITICAL);
        assertThat(Severity.fromScore(8.9)).isEqualTo(Severity.HIGH);
        assertThat(Severity.fromScore(7.0)).isEqualTo(Severity.HIGH);
        assertThat(Severity.fromScore(6.9)).isEqualTo(Severity.MEDIUM);
        assertThat(Severity.fromScore(4.0)).isEqualTo(Severity.MEDIUM);
        assertThat(Severity.fromScore(3.9)).isEqualTo(Severity.LOW);
        assertThat(Severity.fromScore(0.1)).isEqualTo(Severity.LOW);
        assertThat(Severity.fromScore(0.0)).isEqualTo(Severity.UNKNOWN);
    }

    @Test
    void comparesBands() {
        assertThat(Severity.HIGH.atLeast(Severity.MEDIUM)).isTrue();
        assertThat(Severity.HIGH.atLeast(Severity.HIGH)).isTrue();
        assertThat(Severity.MEDIUM.atLeast(Severity.HIGH)).isFalse();
    }

    // An unrated advisory must not be filtered away by a LOW threshold, or a real finding could be
    // hidden simply because nobody scored it yet.
    @Test
    void unknownIsNeverConsideredAboveAThreshold() {
        assertThat(Severity.UNKNOWN.atLeast(Severity.LOW)).isFalse();
        assertThat(Severity.UNKNOWN.atLeast(Severity.UNKNOWN)).isTrue();
        assertThat(Severity.LOW.atLeast(Severity.UNKNOWN)).isTrue();
        assertThat(Severity.LOW.atLeast(null)).isTrue();
    }

    @Test
    void picksTheHigherBand() {
        assertThat(Severity.LOW.max(Severity.CRITICAL)).isEqualTo(Severity.CRITICAL);
        assertThat(Severity.CRITICAL.max(Severity.LOW)).isEqualTo(Severity.CRITICAL);
        assertThat(Severity.MEDIUM.max(null)).isEqualTo(Severity.MEDIUM);
    }
}
