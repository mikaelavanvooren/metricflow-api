package com.metricflow.api;

import org.junit.jupiter.api.Test;
import org.springdoc.core.models.GroupedOpenApi;
import org.springdoc.webmvc.api.OpenApiWebMvcResource;
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

    // A misconfigured docs setup fails at context startup rather than at compile time, so the
    // resource that serves the documents and the path-filtered groups are both asserted. The
    // third group, security, is conditional and absent unless that feature is enabled.
    @Test
    void apiDocumentationBootstrapped() {
        assertThat(context.getBeansOfType(OpenApiWebMvcResource.class)).isNotEmpty();
        assertThat(context.getBeansOfType(GroupedOpenApi.class)).hasSize(2);
    }
}
