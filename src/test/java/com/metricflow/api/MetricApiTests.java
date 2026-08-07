package com.metricflow.api;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// MetricsService keeps state in a singleton map, so these tests assert containment rather
// than absolute collection sizes to stay independent of execution order.
@SpringBootTest
@AutoConfigureMockMvc
class MetricApiTests {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    private JsonNode createMetric(String name, double value, String unit) throws Exception {
        String body = mockMvc.perform(post("/api/v1/metrics")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(String.format("{\"name\":\"%s\",\"value\":%s,\"unit\":\"%s\"}", name, value, unit)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return MAPPER.readTree(body);
    }

    @Test
    void createReturnsPersistedMetricWithGeneratedId() throws Exception {
        JsonNode created = createMetric("requests_per_second", 12.5, "rps");

        assertThat(created.get("id").asLong()).isPositive();
        assertThat(created.get("name").asString()).isEqualTo("requests_per_second");
        assertThat(created.get("value").asDouble()).isEqualTo(12.5);
        assertThat(created.get("unit").asString()).isEqualTo("rps");
    }

    @Test
    void listIncludesCreatedMetric() throws Exception {
        createMetric("cache_hit_ratio", 0.91, "ratio");

        mockMvc.perform(get("/api/v1/metrics"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.name == 'cache_hit_ratio')].value").value(0.91));
    }

    @Test
    void fetchesMetricById() throws Exception {
        long id = createMetric("error_rate", 0.02, "ratio").get("id").asLong();

        mockMvc.perform(get("/api/v1/metrics/{id}", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id))
                .andExpect(jsonPath("$.name").value("error_rate"));
    }

    // Documented behaviour and actual behaviour differ: MetricsService.findById returns null
    // for an unknown id, which Spring renders as 200 with an empty body rather than 404.
    @Test
    void unknownMetricIdReturnsEmptyBodyNotNotFound() throws Exception {
        mockMvc.perform(get("/api/v1/metrics/{id}", 999999))
                .andExpect(status().isOk())
                .andExpect(content().string(""));
    }
}
