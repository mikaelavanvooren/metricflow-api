package com.metricflow.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// Cover for the two grouped documents SwaggerConfig publishes, and for the group isolation
// between them: the public document must never leak the internal dashboard endpoints.
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
}
