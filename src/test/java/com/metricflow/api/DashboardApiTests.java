package com.metricflow.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// DashboardService keeps state in a singleton map, so each test uses owner emails unique to
// itself and filters by owner instead of asserting absolute collection sizes.
@SpringBootTest
@AutoConfigureMockMvc
class DashboardApiTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    private JsonNode createDashboard(String title, String owner, boolean shared) throws Exception {
        String body = mockMvc.perform(post("/api/v1/dashboards")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(String.format("{\"title\":\"%s\",\"owner\":\"%s\",\"shared\":%s}", title, owner, shared)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return MAPPER.readTree(body);
    }

    @Test
    void createReturnsPersistedDashboardWithGeneratedId() throws Exception {
        JsonNode created = createDashboard("Revenue", "create@metricflow.test", false);

        assertThat(created.get("id").asLong()).isPositive();
        assertThat(created.get("title").asText()).isEqualTo("Revenue");
        assertThat(created.get("owner").asText()).isEqualTo("create@metricflow.test");
        assertThat(created.get("shared").asBoolean()).isFalse();
    }

    @Test
    void filtersByOwner() throws Exception {
        createDashboard("Latency", "owner-a@metricflow.test", false);
        createDashboard("Throughput", "owner-b@metricflow.test", false);

        mockMvc.perform(get("/api/v1/dashboards").param("owner", "owner-a@metricflow.test"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].title").value("Latency"))
                .andExpect(jsonPath("$[*].owner").value("owner-a@metricflow.test"));
    }

    @Test
    void filtersBySharedOnly() throws Exception {
        createDashboard("Private board", "shared@metricflow.test", false);
        createDashboard("Shared board", "shared@metricflow.test", true);

        mockMvc.perform(get("/api/v1/dashboards")
                        .param("owner", "shared@metricflow.test")
                        .param("sharedOnly", "true"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].title").value("Shared board"));
    }

    @Test
    void sharedOnlyDefaultsToFalse() throws Exception {
        createDashboard("Unshared", "default@metricflow.test", false);

        mockMvc.perform(get("/api/v1/dashboards").param("owner", "default@metricflow.test"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].title").value("Unshared"));
    }

    // Documented behaviour and actual behaviour differ: deleteDashboard is declared void on a
    // @DeleteMapping, so Spring returns 200 rather than the documented 204.
    @Test
    void deleteRemovesDashboardAndReturnsOk() throws Exception {
        long id = createDashboard("Doomed", "delete@metricflow.test", false).get("id").asLong();

        mockMvc.perform(delete("/api/v1/dashboards/{id}", id))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/v1/dashboards").param("owner", "delete@metricflow.test"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isEmpty());
    }

    @Test
    void deletingUnknownDashboardIsTolerated() throws Exception {
        mockMvc.perform(delete("/api/v1/dashboards/{id}", 999999))
                .andExpect(status().isOk());
    }
}
