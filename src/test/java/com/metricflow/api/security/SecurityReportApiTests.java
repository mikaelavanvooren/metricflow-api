package com.metricflow.api.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = "metricflow.security.enabled=true")
class SecurityReportApiTests {

    private static final DependencyCoordinate SPRING_BOOT =
            new DependencyCoordinate("org.springframework.boot", "spring-boot", "2.7.18", "compile");

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private SecurityScanService scanService;

    private static Vulnerability vulnerability() {
        return new Vulnerability(
                "GHSA-rc42-6c7j-7h5r",
                Collections.singletonList("CVE-2025-22235"),
                Severity.HIGH,
                7.3,
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                "Spring Boot EndpointRequest.to() creates a wrong matcher",
                Arrays.asList("3.3.11", "3.4.5"),
                Collections.singletonList("https://spring.io/security/cve-2025-22235"),
                "2025-04-28T09:31:53Z",
                "2026-02-04T02:35:01Z");
    }

    private static SecurityScanReport report() {
        return new SecurityScanReport(
                "1786000000000",
                "2026-08-06T10:00:00Z",
                "osv.dev",
                86,
                Collections.singletonList(
                        new VulnerableDependency(SPRING_BOOT, Collections.singletonList(vulnerability()))),
                Arrays.asList(
                        ConfigFinding.failing("spring-boot-supported", "Spring Boot receives security patches",
                                Severity.HIGH, "Spring Boot 2.7.18 is past end of OSS support.",
                                "Upgrade to a supported Spring Boot line."),
                        ConfigFinding.passing("h2-console-disabled", "H2 web console is disabled",
                                "The H2 console is disabled.")));
    }

    @BeforeEach
    void setUp() {
        given(scanService.scan(anyBoolean())).willReturn(report());
        given(scanService.scan(anyBoolean(), any(Severity.class))).willReturn(report());
    }

    @Test
    void scanReturnsDependencyAndConfigurationFindings() throws Exception {
        mockMvc.perform(get("/api/v1/security/scan"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scanId").value("1786000000000"))
                .andExpect(jsonPath("$.source").value("osv.dev"))
                .andExpect(jsonPath("$.dependenciesScanned").value(86))
                .andExpect(jsonPath("$.vulnerableDependencies").value(1))
                .andExpect(jsonPath("$.totalVulnerabilities").value(1))
                .andExpect(jsonPath("$.failingConfigChecks").value(1))
                .andExpect(jsonPath("$.totalFindings").value(2))
                .andExpect(jsonPath("$.highestSeverity").value("HIGH"))
                .andExpect(jsonPath("$.countsBySeverity.HIGH").value(2));
    }

    /** The dashboard renders straight off these field names, so their shape is part of the contract. */
    @Test
    void scanExposesTheFieldsTheDashboardReads() throws Exception {
        mockMvc.perform(get("/api/v1/security/scan"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.dependencyFindings[0].dependency.mavenName")
                        .value("org.springframework.boot:spring-boot"))
                .andExpect(jsonPath("$.dependencyFindings[0].dependency.version").value("2.7.18"))
                .andExpect(jsonPath("$.dependencyFindings[0].dependency.purl")
                        .value("pkg:maven/org.springframework.boot/spring-boot@2.7.18"))
                .andExpect(jsonPath("$.dependencyFindings[0].highestSeverity").value("HIGH"))
                .andExpect(jsonPath("$.dependencyFindings[0].vulnerabilities[0].id").value("GHSA-rc42-6c7j-7h5r"))
                .andExpect(jsonPath("$.dependencyFindings[0].vulnerabilities[0].cvssScore").value(7.3))
                .andExpect(jsonPath("$.dependencyFindings[0].vulnerabilities[0].detailsUrl")
                        .value("https://osv.dev/vulnerability/GHSA-rc42-6c7j-7h5r"))
                .andExpect(jsonPath("$.dependencyFindings[0].vulnerabilities[0].fixedVersions[0]").value("3.3.11"))
                .andExpect(jsonPath("$.configFindings[0].id").value("spring-boot-supported"))
                .andExpect(jsonPath("$.configFindings[0].passing").value(false))
                .andExpect(jsonPath("$.configFindings[0].remediation").isNotEmpty())
                .andExpect(jsonPath("$.configFindings[1].passing").value(true));
    }

    @Test
    void scanAcceptsAMinimumSeverity() throws Exception {
        mockMvc.perform(get("/api/v1/security/scan").param("minSeverity", "high"))
                .andExpect(status().isOk());

        org.mockito.Mockito.verify(scanService).scan(false, Severity.HIGH);
    }

    @Test
    void scanRefreshBypassesTheCache() throws Exception {
        mockMvc.perform(get("/api/v1/security/scan").param("refresh", "true"))
                .andExpect(status().isOk());

        org.mockito.Mockito.verify(scanService).scan(true, Severity.UNKNOWN);
    }

    @Test
    void scanRejectsAnUnrecognisedSeverity() throws Exception {
        mockMvc.perform(get("/api/v1/security/scan").param("minSeverity", "SEVERE"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("SEVERE")));
    }

    @Test
    void summaryReturnsCountsWithoutFindingDetail() throws Exception {
        mockMvc.perform(get("/api/v1/security/summary"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalFindings").value(2))
                .andExpect(jsonPath("$.totalVulnerabilities").value(1))
                .andExpect(jsonPath("$.failingConfigChecks").value(1))
                .andExpect(jsonPath("$.highestSeverity").value("HIGH"))
                .andExpect(jsonPath("$.countsBySeverity.HIGH").value(2))
                .andExpect(jsonPath("$.dependencyFindings").doesNotExist());
    }

    @Test
    void historyReturnsRecordedScans() throws Exception {
        ScanSnapshot snapshot = ScanSnapshot.from(report());
        given(scanService.history()).willReturn(Collections.singletonList(snapshot));

        mockMvc.perform(get("/api/v1/security/history"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].scanId").value("1786000000000"))
                .andExpect(jsonPath("$[0].totalVulnerabilities").value(1))
                .andExpect(jsonPath("$[0].failingConfigChecks").value(1))
                .andExpect(jsonPath("$[0].entries.length()").value(2));
    }

    @Test
    void diffReportsFixedAndIntroducedFindings() throws Exception {
        ScanSnapshot before = ScanSnapshot.from(report());
        ScanSnapshot after = new ScanSnapshot();
        after.setScanId("1786000600000");
        after.setScannedAt("2026-08-06T10:10:00Z");
        given(scanService.diff(null, null)).willReturn(ScanDiff.between(before, after));

        mockMvc.perform(get("/api/v1/security/diff"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.baseline").value(false))
                .andExpect(jsonPath("$.fromScanId").value("1786000000000"))
                .andExpect(jsonPath("$.toScanId").value("1786000600000"))
                .andExpect(jsonPath("$.fixedCount").value(2))
                .andExpect(jsonPath("$.introducedCount").value(0))
                .andExpect(jsonPath("$.fixed[0].advisoryId").value("GHSA-rc42-6c7j-7h5r"))
                .andExpect(jsonPath("$.fixed[0].label").value("org.springframework.boot:spring-boot 2.7.18"));
    }

    @Test
    void diffPassesExplicitScanIdsThrough() throws Exception {
        given(scanService.diff("100", "200")).willReturn(ScanDiff.between(null, ScanSnapshot.from(report())));

        mockMvc.perform(get("/api/v1/security/diff").param("from", "100").param("to", "200"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.baseline").value(true));
    }

    /** An unproducible scan must read as unavailable, never as an empty and reassuring result. */
    @Test
    void reportsServiceUnavailableWhenAScanCannotBeProduced() throws Exception {
        willThrow(new ScanUnavailableException("Dependency inventory is missing from the classpath."))
                .given(scanService).scan(anyBoolean(), any(Severity.class));

        mockMvc.perform(get("/api/v1/security/scan"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value(503))
                .andExpect(jsonPath("$.error").value("Scan unavailable"))
                .andExpect(jsonPath("$.message")
                        .value(org.hamcrest.Matchers.containsString("Dependency inventory")));
    }

    @Test
    void reportsServiceUnavailableWhenThereIsNoHistoryToDiff() throws Exception {
        willThrow(new ScanUnavailableException("No scan has been recorded yet."))
                .given(scanService).diff(eq(null), eq(null));

        mockMvc.perform(get("/api/v1/security/diff"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value(503));
    }

    @Test
    void documentsTheSecurityGroupInSwagger() throws Exception {
        mockMvc.perform(get("/swagger-resources"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.name == 'security')]").exists());

        mockMvc.perform(get("/v2/api-docs").param("group", "security"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/api/v1/security/scan']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/security/summary']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/security/history']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/security/diff']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/metrics']").doesNotExist());
    }

    /** The security endpoints must not leak into the documentation the other groups publish. */
    @Test
    void keepsSecurityPathsOutOfTheOtherGroups() throws Exception {
        for (String group : new String[] { "public-metrics", "internal-dashboards" }) {
            mockMvc.perform(get("/v2/api-docs").param("group", group))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.paths['/api/v1/security/scan']").doesNotExist());
        }
    }

    @Test
    void servesTheDashboardPage() throws Exception {
        mockMvc.perform(get("/security/index.html"))
                .andExpect(status().isOk());
    }
}
