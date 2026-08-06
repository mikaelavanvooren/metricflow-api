package com.metricflow.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// The two path-filtered groups are the contract SwaggerConfig exists to provide, and a broken
// docs configuration is the kind of failure that only shows up at runtime, so it is asserted
// against a started context rather than by inspecting the bean definitions.
@SpringBootTest
@AutoConfigureMockMvc
class SwaggerDocsTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void publishesBothDocumentationGroups() throws Exception {
        mockMvc.perform(get("/v3/api-docs/swagger-config"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.urls[?(@.name == 'public-metrics')]").exists())
                .andExpect(jsonPath("$.urls[?(@.name == 'internal-dashboards')]").exists());
    }

    @Test
    void publicGroupContainsOnlyMetricsPaths() throws Exception {
        mockMvc.perform(get("/v3/api-docs/public-metrics"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/api/v1/metrics']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/metrics/{id}']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/dashboards']").doesNotExist());
    }

    @Test
    void internalGroupContainsOnlyDashboardPaths() throws Exception {
        mockMvc.perform(get("/v3/api-docs/internal-dashboards"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/api/v1/dashboards']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/dashboards/{id}']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/metrics']").doesNotExist());
    }

    // The documented response codes are part of the published contract, and they previously
    // contradicted what the endpoints actually returned.
    @Test
    void documentsTheStatusCodesTheEndpointsActuallyReturn() throws Exception {
        mockMvc.perform(get("/v3/api-docs/internal-dashboards"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/api/v1/dashboards'].post.responses['201']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/dashboards/{id}'].delete.responses['204']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/dashboards/{id}'].delete.responses['404']").exists())
                // No authentication or ownership check exists, so these were unreachable.
                .andExpect(jsonPath("$.paths['/api/v1/dashboards'].get.responses['401']").doesNotExist())
                .andExpect(jsonPath("$.paths['/api/v1/dashboards/{id}'].delete.responses['403']").doesNotExist());
    }
}
