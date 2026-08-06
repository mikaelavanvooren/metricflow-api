package com.metricflow.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// Regression cover for the springfox / Boot 2.6+ path-matching incompatibility: without
// spring.mvc.pathmatch.matching-strategy=ant_path_matcher the context does not even start,
// and these two grouped documents are what SwaggerConfig is expected to publish.
@SpringBootTest
@AutoConfigureMockMvc
class SwaggerDocsTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void publishesBothDocumentationGroups() throws Exception {
        mockMvc.perform(get("/swagger-resources"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.name == 'public-metrics')]").exists())
                .andExpect(jsonPath("$[?(@.name == 'internal-dashboards')]").exists());
    }

    @Test
    void publicGroupContainsOnlyMetricsPaths() throws Exception {
        mockMvc.perform(get("/v2/api-docs").param("group", "public-metrics"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/api/v1/metrics']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/metrics/{id}']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/dashboards']").doesNotExist());
    }

    @Test
    void internalGroupContainsOnlyDashboardPaths() throws Exception {
        mockMvc.perform(get("/v2/api-docs").param("group", "internal-dashboards"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.paths['/api/v1/dashboards']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/dashboards/{id}']").exists())
                .andExpect(jsonPath("$.paths['/api/v1/metrics']").doesNotExist());
    }
}
