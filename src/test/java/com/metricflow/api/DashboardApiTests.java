package com.metricflow.api;

import tools.jackson.databind.ObjectMapper;
import com.metricflow.api.model.Dashboard;
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
class DashboardApiTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void createAndListDashboard() throws Exception {
        Dashboard dashboard = new Dashboard();
        dashboard.setTitle("Revenue Overview");
        dashboard.setOwner("platform@metricflow.example.com");
        dashboard.setShared(true);

        // Create
        String body = objectMapper.writeValueAsString(dashboard);
        mockMvc.perform(post("/api/v1/dashboards")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title").value("Revenue Overview"))
                .andExpect(jsonPath("$.owner").value("platform@metricflow.example.com"))
                .andExpect(jsonPath("$.shared").value(true))
                .andExpect(jsonPath("$.id").exists());

        // List all
        mockMvc.perform(get("/api/v1/dashboards"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].title").value("Revenue Overview"));

        // Filter by owner
        mockMvc.perform(get("/api/v1/dashboards").param("owner", "platform@metricflow.example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].owner").value("platform@metricflow.example.com"));

        // Filter by owner with no match
        mockMvc.perform(get("/api/v1/dashboards").param("owner", "nobody@example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));

        // sharedOnly filter
        mockMvc.perform(get("/api/v1/dashboards").param("sharedOnly", "true"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].shared").value(true));
    }

    @Test
    void deleteDashboard() throws Exception {
        Dashboard dashboard = new Dashboard();
        dashboard.setTitle("Transient Dashboard");
        dashboard.setOwner("owner@metricflow.example.com");
        dashboard.setShared(false);

        String body = objectMapper.writeValueAsString(dashboard);
        String created = mockMvc.perform(post("/api/v1/dashboards")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andReturn().getResponse().getContentAsString();
        Long id = objectMapper.readTree(created).get("id").asLong();

        mockMvc.perform(delete("/api/v1/dashboards/{id}", id))
                .andExpect(status().isOk());

        // After deletion, listing should not contain it
        mockMvc.perform(get("/api/v1/dashboards").param("owner", "owner@metricflow.example.com"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(0));
    }
}
