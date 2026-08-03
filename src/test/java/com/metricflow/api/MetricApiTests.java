package com.metricflow.api;

import tools.jackson.databind.ObjectMapper;
import com.metricflow.api.model.Metric;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class MetricApiTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void createAndFetchMetric() throws Exception {
        Metric metric = new Metric();
        metric.setName("active_users");
        metric.setValue(12345.67);
        metric.setUnit("count");

        String body = objectMapper.writeValueAsString(metric);

        // Create
        String created = mockMvc.perform(post("/api/v1/metrics")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("active_users"))
                .andExpect(jsonPath("$.value").value(12345.67))
                .andExpect(jsonPath("$.unit").value("count"))
                .andExpect(jsonPath("$.id").exists())
                .andReturn().getResponse().getContentAsString();

        Long id = objectMapper.readTree(created).get("id").asLong();

        // Fetch by id
        mockMvc.perform(get("/api/v1/metrics/{id}", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("active_users"))
                .andExpect(jsonPath("$.value").value(12345.67));

        // List all
        mockMvc.perform(get("/api/v1/metrics"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].name").value("active_users"));
    }

    @Test
    void fetchMissingMetricReturnsNullBody() throws Exception {
        // The service returns null for unknown ids; Spring serializes that as an empty body.
        mockMvc.perform(get("/api/v1/metrics/{id}", 999999))
                .andExpect(status().isOk());
    }
}
