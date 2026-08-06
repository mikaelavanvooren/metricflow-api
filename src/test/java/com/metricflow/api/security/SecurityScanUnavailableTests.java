package com.metricflow.api.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Covers the unavailable path through the real service rather than a mock: the dependency inventory
 * reports nothing, which is what happens when the application runs from classes the Maven build did
 * not produce.
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "metricflow.security.enabled=true",
        // Keep any history writes inside target/ rather than the project directory.
        "metricflow.security.snapshot-dir=target/test-snapshots-unavailable"
})
class SecurityScanUnavailableTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void scanReportsUnavailableRatherThanAnEmptyResult() throws Exception {
        mockMvc.perform(get("/api/v1/security/scan"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value(503))
                .andExpect(jsonPath("$.error").value("Scan unavailable"))
                .andExpect(jsonPath("$.message")
                        .value(org.hamcrest.Matchers.containsString("metricflow-dependencies.txt")));
    }

    @Test
    void summaryReportsUnavailable() throws Exception {
        mockMvc.perform(get("/api/v1/security/summary"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.status").value(503));
    }

    @Test
    void diffReportsUnavailableWithNoRecordedScans() throws Exception {
        mockMvc.perform(get("/api/v1/security/diff"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.message")
                        .value(org.hamcrest.Matchers.containsString("No scan has been recorded")));
    }

    /** History is legitimately empty rather than unavailable: nothing has been recorded yet. */
    @Test
    void historyIsEmptyRatherThanUnavailable() throws Exception {
        mockMvc.perform(get("/api/v1/security/history"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$").isEmpty());
    }

    @TestConfiguration
    static class MissingInventoryConfiguration {

        @Bean
        @Primary
        DependencySource missingInventory() {
            return Optional::empty;
        }
    }
}
