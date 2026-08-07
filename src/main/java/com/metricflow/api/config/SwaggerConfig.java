package com.metricflow.api.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    // Public-facing docs: only the metrics endpoints, versioned separately
    // from internal dashboard config endpoints.
    @Bean
    public GroupedOpenApi publicApiDocs() {
        return GroupedOpenApi.builder()
                .group("public-metrics")
                .packagesToScan("com.metricflow.api.controller")
                // The bare collection path is listed alongside the wildcard so it is grouped
                // regardless of how the matcher treats a zero-segment /**.
                .pathsToMatch("/api/v1/metrics", "/api/v1/metrics/**")
                .build();
    }

    // Internal docs: dashboard management, not exposed to external partners.
    @Bean
    public GroupedOpenApi internalApiDocs() {
        return GroupedOpenApi.builder()
                .group("internal-dashboards")
                .packagesToScan("com.metricflow.api.controller")
                .pathsToMatch("/api/v1/dashboards", "/api/v1/dashboards/**")
                .build();
    }

    // Security docs: dependency and configuration findings. Registered only when the feature is
    // enabled, since the other two groups filter by path and would otherwise leave these
    // endpoints undocumented while still routable.
    @Bean
    @ConditionalOnProperty(prefix = "metricflow.security", name = "enabled", havingValue = "true")
    public GroupedOpenApi securityApiDocs() {
        return GroupedOpenApi.builder()
                .group("security")
                .packagesToScan("com.metricflow.api.security")
                .pathsToMatch("/api/v1/security", "/api/v1/security/**")
                .build();
    }

    @Bean
    public OpenAPI metricflowOpenApi() {
        return new OpenAPI().info(new Info()
                .title("MetricFlow API")
                .description("Metrics and dashboard endpoints for the MetricFlow analytics platform")
                .version("0.1.0")
                .termsOfService("https://metricflow.example.com/terms")
                .contact(new Contact()
                        .name("Platform Team")
                        .url("https://metricflow.example.com")
                        .email("platform@metricflow.example.com"))
                .license(new License().name("Internal Use Only")));
    }
}
