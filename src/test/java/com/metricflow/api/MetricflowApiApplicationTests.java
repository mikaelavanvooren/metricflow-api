package com.metricflow.api;

import org.junit.jupiter.api.Test;
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

    // springfox 3.0.0 only bootstraps when spring.mvc.pathmatch.matching-strategy is
    // ant_path_matcher; this bean is the one that fails without it.
    @Test
    void springfoxBootstrapped() {
        assertThat(context.containsBean("documentationPluginsBootstrapper")).isTrue();
    }
}
