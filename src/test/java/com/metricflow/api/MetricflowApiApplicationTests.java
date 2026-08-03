package com.metricflow.api;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class MetricflowApiApplicationTests {

    @Test
    void contextLoads() {
        // Verifies the full application context boots on Spring Boot 4:
        // JPA (Hibernate 6) + H2 + springdoc-openapi + WebMVC auto-configuration.
    }
}
