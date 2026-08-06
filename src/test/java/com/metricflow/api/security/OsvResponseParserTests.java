package com.metricflow.api.security;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import java.io.IOException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class OsvResponseParserTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode fixture(String name) throws IOException {
        return MAPPER.readTree(new ClassPathResource("osv/" + name).getInputStream());
    }

    private static JsonNode json(String raw) throws IOException {
        return MAPPER.readTree(raw);
    }

    @Test
    void prefersTheAdvisorySeverityLabel() throws IOException {
        Vulnerability vulnerability = OsvResponseParser
                .parseVulnerability(fixture("advisory-with-label.json"), "org.springframework.boot:spring-boot")
                .orElseThrow(AssertionError::new);

        assertThat(vulnerability.getId()).isEqualTo("GHSA-rc42-6c7j-7h5r");
        assertThat(vulnerability.getSeverity()).isEqualTo(Severity.HIGH);
        assertThat(vulnerability.getAliases()).containsExactly("CVE-2025-22235");
        assertThat(vulnerability.getCvssScore()).isEqualTo(7.3);
        assertThat(vulnerability.getCvssVector()).isEqualTo("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
        assertThat(vulnerability.getSummary()).startsWith("Spring Boot EndpointRequest.to()");
        assertThat(vulnerability.getDetailsUrl()).isEqualTo("https://osv.dev/vulnerability/GHSA-rc42-6c7j-7h5r");
    }

    /**
     * Fix versions are per artifact, and one advisory routinely covers several. Listing another
     * artifact's fix version would send the reader chasing an upgrade that does not exist.
     */
    @Test
    void collectsFixVersionsForTheQueriedPackageOnly() throws IOException {
        Vulnerability vulnerability = OsvResponseParser
                .parseVulnerability(fixture("advisory-with-label.json"), "org.springframework.boot:spring-boot")
                .orElseThrow(AssertionError::new);

        assertThat(vulnerability.getFixedVersions()).containsExactly("3.3.11", "3.4.5");
        assertThat(vulnerability.getFixedVersions()).doesNotContain("99.0.0");
    }

    @Test
    void deduplicatesReferences() throws IOException {
        Vulnerability vulnerability = OsvResponseParser
                .parseVulnerability(fixture("advisory-with-label.json"), "org.springframework.boot:spring-boot")
                .orElseThrow(AssertionError::new);

        assertThat(vulnerability.getReferences()).containsExactly(
                "https://nvd.nist.gov/vuln/detail/CVE-2025-22235",
                "https://spring.io/security/cve-2025-22235");
    }

    @Test
    void fallsBackToTheCvssVectorWhenNoLabelIsPublished() throws IOException {
        Vulnerability vulnerability = OsvResponseParser
                .parseVulnerability(fixture("advisory-without-label.json"), "com.example:widget")
                .orElseThrow(AssertionError::new);

        assertThat(vulnerability.getSeverity()).isEqualTo(Severity.CRITICAL);
        assertThat(vulnerability.getCvssScore()).isEqualTo(9.8);
        assertThat(vulnerability.getFixedVersions()).containsExactly("2.0.0");
    }

    @Test
    void usesTheFirstLineOfDetailsWhenThereIsNoSummary() throws IOException {
        Vulnerability vulnerability = OsvResponseParser
                .parseVulnerability(fixture("advisory-without-label.json"), "com.example:widget")
                .orElseThrow(AssertionError::new);

        assertThat(vulnerability.getSummary()).isEqualTo("First line of a long markdown description.");
    }

    @Test
    void leavesSeverityUnknownWhenNeitherLabelNorScorableVectorExists() throws IOException {
        Vulnerability vulnerability = OsvResponseParser
                .parseVulnerability(json("{\"id\":\"GHSA-x\",\"severity\":[{\"type\":\"CVSS_V2\",\"score\":\"AV:N/AC:L\"}]}"), "com.example:x")
                .orElseThrow(AssertionError::new);

        assertThat(vulnerability.getSeverity()).isEqualTo(Severity.UNKNOWN);
        assertThat(vulnerability.getCvssScore()).isNull();
    }

    @Test
    void rejectsDocumentsWithoutAnId() throws IOException {
        assertThat(OsvResponseParser.parseVulnerability(null, "com.example:x")).isEmpty();
        assertThat(OsvResponseParser.parseVulnerability(json("{}"), "com.example:x")).isEmpty();
        assertThat(OsvResponseParser.parseVulnerability(json("{\"id\":\"\"}"), "com.example:x")).isEmpty();
    }

    @Test
    void readsBatchIdsPositionally() throws IOException {
        JsonNode response = json("{\"results\":["
                + "{\"vulns\":[{\"id\":\"GHSA-a\"},{\"id\":\"GHSA-b\"}]},"
                + "{},"
                + "{\"vulns\":[{\"id\":\"GHSA-c\"}]}]}");

        assertThat(OsvResponseParser.parseBatchIds(response, 3))
                .containsExactly(
                        java.util.Arrays.asList("GHSA-a", "GHSA-b"),
                        java.util.Collections.emptyList(),
                        java.util.Collections.singletonList("GHSA-c"));
    }

    /**
     * OSV omits trailing entries for queries with no matches, so the result must still be padded to
     * the number of queries or every dependency after a gap would be attributed the wrong advisories.
     */
    @Test
    void padsBatchResultsToTheQueryCount() throws IOException {
        JsonNode response = json("{\"results\":[{\"vulns\":[{\"id\":\"GHSA-a\"}]}]}");

        assertThat(OsvResponseParser.parseBatchIds(response, 3)).hasSize(3);
        assertThat(OsvResponseParser.parseBatchIds(response, 3).get(2)).isEmpty();
        assertThat(OsvResponseParser.parseBatchIds(null, 2)).hasSize(2);
    }

    @Test
    void toleratesAnEmptyBatchResponse() throws IOException {
        assertThat(OsvResponseParser.parseBatchIds(json("{}"), 1))
                .containsExactly(java.util.Collections.<String>emptyList());
    }

    @Test
    void parsesRealAdvisoryShapeWithoutFixVersions() throws IOException {
        // Only last_affected, no fixed event: the 2.7 line this project sits on never got a patch.
        Optional<Vulnerability> parsed = OsvResponseParser.parseVulnerability(
                json("{\"id\":\"GHSA-y\",\"database_specific\":{\"severity\":\"MODERATE\"},"
                        + "\"affected\":[{\"package\":{\"name\":\"a:b\"},\"ranges\":[{\"events\":"
                        + "[{\"introduced\":\"0\"},{\"last_affected\":\"2.7.18\"}]}]}]}"),
                "a:b");

        assertThat(parsed).isPresent();
        assertThat(parsed.get().getSeverity()).isEqualTo(Severity.MEDIUM);
        assertThat(parsed.get().getFixedVersions()).isEmpty();
    }
}
