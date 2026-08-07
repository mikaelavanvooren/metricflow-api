package com.metricflow.api.security;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CvssV3Tests {

    // Vectors and expected scores taken from published advisories, so a regression in the base
    // score equations shows up as a concrete mismatch rather than a plausible-looking number.
    @Test
    void scoresPublishedVectors() {
        // CVE-2025-22235, the Spring Boot advisory this project is actually affected by.
        assertScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 7.3);
        // Log4Shell, the canonical 10.0 with a scope change.
        assertScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0);
        assertScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8);
        assertScore("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9);
        assertScore("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5);
        assertScore("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N", 4.3);
    }

    @Test
    void scoresZeroWhenThereIsNoImpact() {
        assertScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0);
    }

    @Test
    void rejectsVectorsItCannotScore() {
        assertThat(CvssV3.baseScore(null)).isEmpty();
        assertThat(CvssV3.baseScore("")).isEmpty();
        assertThat(CvssV3.baseScore("   ")).isEmpty();
        // CVSS v2 and v4 use different equations, so guessing would be worse than declining.
        assertThat(CvssV3.baseScore("AV:N/AC:L/Au:N/C:P/I:P/A:P")).isEmpty();
        assertThat(CvssV3.baseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N")).isEmpty();
        // Missing base metrics.
        assertThat(CvssV3.baseScore("CVSS:3.1/AV:N/AC:L")).isEmpty();
        assertThat(CvssV3.baseScore("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).isEmpty();
    }

    @Test
    void isCaseAndWhitespaceTolerant() {
        assertScore(" cvss:3.1/av:n/ac:l/pr:n/ui:n/s:u/c:h/i:h/a:h ", 9.8);
    }

    /**
     * The specification's Roundup returns the smallest one-decimal value that is at least the input.
     * Naive rounding of a value like 8.6, which has no exact binary representation, lands a tenth
     * low, so this behaviour is pinned directly.
     */
    @Test
    void roundsUpToOneDecimal() {
        assertThat(CvssV3.roundUp(4.0)).isEqualTo(4.0);
        assertThat(CvssV3.roundUp(4.01)).isEqualTo(4.1);
        assertThat(CvssV3.roundUp(8.6)).isEqualTo(8.6);
        assertThat(CvssV3.roundUp(9.995)).isEqualTo(10.0);
    }

    private static void assertScore(String vector, double expected) {
        assertThat(CvssV3.baseScore(vector))
                .withFailMessage("expected %s to score %s but was %s",
                        vector, expected, CvssV3.baseScore(vector))
                .contains(expected);
    }
}
