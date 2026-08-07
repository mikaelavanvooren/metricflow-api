package com.metricflow.api.security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * A list of this application's own unpatched advisories is reconnaissance material, and there is no
 * authentication in front of it, so the endpoints must stay off unless explicitly enabled. This
 * fixture deliberately sets no properties: it asserts the shipped default.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityEndpointsDisabledByDefaultTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ApplicationContext context;

    @Test
    void scanIsNotMapped() throws Exception {
        mockMvc.perform(get("/api/v1/security/scan")).andExpect(status().isNotFound());
    }

    @Test
    void noSecurityEndpointIsMapped() throws Exception {
        for (String path : new String[] { "/scan", "/summary", "/history", "/diff" }) {
            mockMvc.perform(get("/api/v1/security" + path)).andExpect(status().isNotFound());
        }
    }

    /** Not merely unmapped: none of the scanning machinery is instantiated at all. */
    @Test
    void noScanningBeansAreCreated() {
        assertThat(context.getBeanNamesForType(SecurityReportController.class)).isEmpty();
        assertThat(context.getBeanNamesForType(SecurityScanService.class)).isEmpty();
        assertThat(context.getBeanNamesForType(OsvClient.class)).isEmpty();
        assertThat(context.getBeanNamesForType(SnapshotStore.class)).isEmpty();
    }

    @Test
    void theSecurityDocumentationGroupIsNotPublished() throws Exception {
        mockMvc.perform(get("/v3/api-docs/swagger-config"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.urls[?(@.name == 'security')]").doesNotExist())
                .andExpect(jsonPath("$.urls[?(@.name == 'public-metrics')]").exists());
    }

    /** The other endpoints must keep working with the feature off. */
    @Test
    void theRestOfTheApiIsUnaffected() throws Exception {
        mockMvc.perform(get("/api/v1/metrics")).andExpect(status().isOk());
        mockMvc.perform(get("/api/v1/dashboards")).andExpect(status().isOk());
    }
}
