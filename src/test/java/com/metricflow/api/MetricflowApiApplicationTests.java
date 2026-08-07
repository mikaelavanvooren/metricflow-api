package com.metricflow.api;

import org.junit.jupiter.api.Test;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class MetricflowApiApplicationTests {

    @Autowired
    private ApplicationContext context;

    @Test
    void contextLoads() {
        assertThat(context).isNotNull();
    }

    @Test
    void springdocGroupsRegistered() {
        assertThat(context.getBeansOfType(GroupedOpenApi.class).values())
                .extracting(GroupedOpenApi::getGroup)
                .containsExactlyInAnyOrder("public-metrics", "internal-dashboards");
    }
}
