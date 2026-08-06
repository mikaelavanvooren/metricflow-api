package com.metricflow.api.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.jsonPath;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Exercises the OSV request and response handling against a stubbed server, so the suite never
 * depends on network access or on what the live database happens to contain today.
 */
class OsvClientTests {

    private static final String BASE_URL = "https://osv.test";
    private static final DependencyCoordinate SPRING_BOOT =
            new DependencyCoordinate("org.springframework.boot", "spring-boot", "2.7.18", "compile");
    private static final DependencyCoordinate H2 =
            new DependencyCoordinate("com.h2database", "h2", "2.1.214", "runtime");

    private RestTemplate restTemplate;
    private MockRestServiceServer server;
    private OsvClient client;

    @BeforeEach
    void setUp() {
        restTemplate = new RestTemplate();
        server = MockRestServiceServer.bindTo(restTemplate).build();
        // Single threaded on purpose: MockRestServiceServer expectations are ordered.
        client = new OsvClient(restTemplate, BASE_URL, 1);
    }

    private void expectBatch(String responseBody) {
        server.expect(requestTo(BASE_URL + "/v1/querybatch"))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andRespond(withSuccess(responseBody, MediaType.APPLICATION_JSON));
    }

    private void expectAdvisory(String id, String responseBody) {
        server.expect(requestTo(BASE_URL + "/v1/vulns/" + id))
                .andExpect(method(org.springframework.http.HttpMethod.GET))
                .andRespond(withSuccess(responseBody, MediaType.APPLICATION_JSON));
    }

    private static String advisory(String id, String severity, String packageName, String fixedVersion) {
        return "{\"id\":\"" + id + "\",\"summary\":\"summary of " + id + "\","
                + "\"database_specific\":{\"severity\":\"" + severity + "\"},"
                + "\"affected\":[{\"package\":{\"name\":\"" + packageName + "\"},"
                + "\"ranges\":[{\"events\":[{\"introduced\":\"0\"},{\"fixed\":\"" + fixedVersion + "\"}]}]}]}";
    }

    @Test
    void sendsOneBatchQueryPerDependency() {
        server.expect(requestTo(BASE_URL + "/v1/querybatch"))
                .andExpect(method(org.springframework.http.HttpMethod.POST))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.queries.length()").value(2))
                .andExpect(jsonPath("$.queries[0].package.name").value("org.springframework.boot:spring-boot"))
                .andExpect(jsonPath("$.queries[0].package.ecosystem").value("Maven"))
                .andExpect(jsonPath("$.queries[0].version").value("2.7.18"))
                .andExpect(jsonPath("$.queries[1].package.name").value("com.h2database:h2"))
                .andRespond(withSuccess("{\"results\":[{},{}]}", MediaType.APPLICATION_JSON));

        assertThat(client.findVulnerabilities(Arrays.asList(SPRING_BOOT, H2))).isEmpty();
        server.verify();
    }

    @Test
    void resolvesAdvisoryDetailForEachMatch() {
        expectBatch("{\"results\":[{\"vulns\":[{\"id\":\"GHSA-a\"},{\"id\":\"GHSA-b\"}]},{}]}");
        expectAdvisory("GHSA-a", advisory("GHSA-a", "HIGH", "org.springframework.boot:spring-boot", "3.3.11"));
        expectAdvisory("GHSA-b", advisory("GHSA-b", "CRITICAL", "org.springframework.boot:spring-boot", "3.4.5"));

        Map<DependencyCoordinate, List<Vulnerability>> found =
                client.findVulnerabilities(Arrays.asList(SPRING_BOOT, H2));

        assertThat(found).containsOnlyKeys(SPRING_BOOT);
        assertThat(found.get(SPRING_BOOT)).extracting(Vulnerability::getId)
                .containsExactlyInAnyOrder("GHSA-a", "GHSA-b");
        assertThat(found.get(SPRING_BOOT)).extracting(Vulnerability::getSeverity)
                .containsExactlyInAnyOrder(Severity.HIGH, Severity.CRITICAL);
        server.verify();
    }

    @Test
    void omitsDependenciesWithNoMatches() {
        expectBatch("{\"results\":[{},{}]}");

        assertThat(client.findVulnerabilities(Arrays.asList(SPRING_BOOT, H2))).isEmpty();
        server.verify();
    }

    /**
     * One advisory frequently covers several artifacts with different fix versions, so it is fetched
     * once per package rather than once overall.
     */
    @Test
    void resolvesSharedAdvisoriesPerPackage() {
        expectBatch("{\"results\":[{\"vulns\":[{\"id\":\"GHSA-shared\"}]},{\"vulns\":[{\"id\":\"GHSA-shared\"}]}]}");
        expectAdvisory("GHSA-shared", advisory("GHSA-shared", "HIGH", "org.springframework.boot:spring-boot", "3.3.11"));
        expectAdvisory("GHSA-shared", advisory("GHSA-shared", "HIGH", "com.h2database:h2", "2.2.220"));

        Map<DependencyCoordinate, List<Vulnerability>> found =
                client.findVulnerabilities(Arrays.asList(SPRING_BOOT, H2));

        assertThat(found).containsOnlyKeys(SPRING_BOOT, H2);
        assertThat(found.get(SPRING_BOOT).get(0).getFixedVersions()).containsExactly("3.3.11");
        assertThat(found.get(H2).get(0).getFixedVersions()).containsExactly("2.2.220");
        server.verify();
    }

    /** Advisory documents are immutable in practice, so the same lookup is not repeated. */
    @Test
    void cachesAdvisoryLookupsAcrossScans() {
        expectBatch("{\"results\":[{\"vulns\":[{\"id\":\"GHSA-a\"}]}]}");
        expectAdvisory("GHSA-a", advisory("GHSA-a", "HIGH", "org.springframework.boot:spring-boot", "3.3.11"));
        expectBatch("{\"results\":[{\"vulns\":[{\"id\":\"GHSA-a\"}]}]}");

        client.findVulnerabilities(Collections.singletonList(SPRING_BOOT));
        Map<DependencyCoordinate, List<Vulnerability>> second =
                client.findVulnerabilities(Collections.singletonList(SPRING_BOOT));

        assertThat(second.get(SPRING_BOOT)).extracting(Vulnerability::getId).containsExactly("GHSA-a");
        server.verify();
    }

    /**
     * A single unreadable advisory should cost that one finding, not the whole scan, since the rest
     * of the report is still accurate and actionable.
     */
    @Test
    void skipsAdvisoriesThatCannotBeFetched() {
        expectBatch("{\"results\":[{\"vulns\":[{\"id\":\"GHSA-ok\"},{\"id\":\"GHSA-broken\"}]}]}");
        expectAdvisory("GHSA-ok", advisory("GHSA-ok", "HIGH", "org.springframework.boot:spring-boot", "3.3.11"));
        server.expect(requestTo(BASE_URL + "/v1/vulns/GHSA-broken")).andRespond(withServerError());

        Map<DependencyCoordinate, List<Vulnerability>> found =
                client.findVulnerabilities(Collections.singletonList(SPRING_BOOT));

        assertThat(found.get(SPRING_BOOT)).extracting(Vulnerability::getId).containsExactly("GHSA-ok");
        server.verify();
    }

    /** An unreachable database must surface as a failure, never as an empty result. */
    @Test
    void raisesWhenTheBatchQueryFails() {
        server.expect(requestTo(BASE_URL + "/v1/querybatch")).andRespond(withServerError());

        assertThatThrownBy(() -> client.findVulnerabilities(Collections.singletonList(SPRING_BOOT)))
                .isInstanceOf(OsvClient.OsvUnavailableException.class);
    }

    @Test
    void raisesWhenTheBatchQueryIsRateLimited() {
        server.expect(requestTo(BASE_URL + "/v1/querybatch"))
                .andRespond(withStatus(org.springframework.http.HttpStatus.TOO_MANY_REQUESTS));

        assertThatThrownBy(() -> client.findVulnerabilities(Collections.singletonList(SPRING_BOOT)))
                .isInstanceOf(OsvClient.OsvUnavailableException.class);
    }

    @Test
    void makesNoRequestForAnEmptyDependencyList() {
        server.expect(ExpectedCount.never(), requestTo(BASE_URL + "/v1/querybatch"))
                .andRespond(withSuccess());

        assertThat(client.findVulnerabilities(Collections.emptyList())).isEmpty();
        assertThat(client.findVulnerabilities(null)).isEmpty();
        server.verify();
    }

    @Test
    void normalisesATrailingSlashOnTheBaseUrl() {
        OsvClient trailing = new OsvClient(restTemplate, BASE_URL + "/", 1);
        expectBatch("{\"results\":[{}]}");

        assertThat(trailing.findVulnerabilities(Collections.singletonList(SPRING_BOOT))).isEmpty();
        server.verify();
    }
}
