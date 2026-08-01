package com.metricflow.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;

@Configuration
public class SwaggerConfig {

    // Public-facing docs: only the metrics endpoints, versioned separately
    // from internal dashboard config endpoints.
    @Bean
    public Docket publicApiDocket() {
        return new Docket(DocumentationType.SWAGGER_2)
                .groupName("public-metrics")
                .apiInfo(apiInfo())
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.metricflow.api.controller"))
                .paths(PathSelectors.ant("/api/v1/metrics/**"))
                .build();
    }

    // Internal docs: dashboard management, not exposed to external partners.
    @Bean
    public Docket internalApiDocket() {
        return new Docket(DocumentationType.SWAGGER_2)
                .groupName("internal-dashboards")
                .apiInfo(apiInfo())
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.metricflow.api.controller"))
                .paths(PathSelectors.ant("/api/v1/dashboards/**"))
                .build();
    }

    private ApiInfo apiInfo() {
        return new ApiInfo(
                "MetricFlow API",
                "Metrics and dashboard endpoints for the MetricFlow analytics platform",
                "0.1.0",
                "https://metricflow.example.com/terms",
                new Contact("Platform Team", "https://metricflow.example.com", "platform@metricflow.example.com"),
                "Internal Use Only",
                "",
                java.util.Collections.emptyList()
        );
    }
}
