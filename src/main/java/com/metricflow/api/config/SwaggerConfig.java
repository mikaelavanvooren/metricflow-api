package com.metricflow.api.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    // Public-facing docs: only the metrics endpoints, versioned separately
    // from internal dashboard config endpoints.
    @Bean
    public GroupedOpenApi publicApiDocket() {
        return GroupedOpenApi.builder()
                .group("public-metrics")
                .pathsToMatch("/api/v1/metrics/**")
                .build();
    }

    // Internal docs: dashboard management, not exposed to external partners.
    @Bean
    public GroupedOpenApi internalApiDocket() {
        return GroupedOpenApi.builder()
                .group("internal-dashboards")
                .pathsToMatch("/api/v1/dashboards/**")
                .build();
    }

    @Bean
    public OpenAPI metricFlowOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("MetricFlow API")
                        .description("Metrics and dashboard endpoints for the MetricFlow analytics platform")
                        .version("0.1.0")
                        .termsOfService("https://metricflow.example.com/terms")
                        .contact(new Contact()
                                .name("Platform Team")
                                .url("https://metricflow.example.com")
                                .email("platform@metricflow.example.com"))
                        .license(new License()
                                .name("Internal Use Only")
                                .url("")));
    }
}
