package com.metricflow.api.security;

import com.metricflow.api.MetricflowApiApplication;
import org.springframework.boot.SpringBootVersion;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.util.ClassUtils;
import org.springframework.web.client.RestTemplate;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Clock;

/**
 * Wiring for the vulnerability scanner. The whole configuration is conditional, so with the feature
 * disabled none of these beans exist and {@code /api/v1/security/**} is simply not mapped.
 */
@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
@ConditionalOnProperty(prefix = "metricflow.security", name = "enabled", havingValue = "true")
public class SecurityScanConfiguration {

    @Bean
    public DependencyInventory dependencyInventory() {
        return new DependencyInventory();
    }

    /**
     * A dedicated RestTemplate: OSV is a third-party service on the request path of an endpoint, so
     * it needs its own timeouts rather than inheriting an application-wide default.
     */
    @Bean
    public RestTemplate osvRestTemplate(RestTemplateBuilder builder, SecurityProperties properties) {
        return builder
                .setConnectTimeout(properties.getConnectTimeout())
                .setReadTimeout(properties.getReadTimeout())
                .build();
    }

    @Bean
    public OsvClient osvClient(RestTemplate osvRestTemplate, SecurityProperties properties) {
        return new OsvClient(osvRestTemplate, properties.getOsvBaseUrl(), properties.getFetchConcurrency());
    }

    @Bean
    public SnapshotStore snapshotStore(SecurityProperties properties) {
        Path directory = Paths.get(properties.getSnapshotDir()).toAbsolutePath();
        return new SnapshotStore(directory, properties.getHistoryLimit());
    }

    @Bean
    public ConfigCheckContext configCheckContext(Environment environment) {
        ClassLoader classLoader = getClass().getClassLoader();
        return new ConfigCheckContext(
                environment,
                SpringBootVersion.getVersion(),
                // Read from an application class, not a library one, so the answer reflects what this
                // project compiles to rather than what its dependencies were built with.
                ConfigCheckContext.readBytecodeMajorVersion(MetricflowApiApplication.class),
                System.getProperty("java.version"),
                className -> ClassUtils.isPresent(className, classLoader));
    }

    // Depends on the source interfaces rather than the concrete reader and HTTP client so a test can
    // substitute either without standing up a network stub.
    @Bean
    public SecurityScanService securityScanService(DependencySource dependencySource,
                                                  AdvisorySource advisorySource,
                                                  ConfigCheckContext configCheckContext,
                                                  SnapshotStore snapshotStore,
                                                  SecurityProperties properties) {
        return new SecurityScanService(dependencySource, advisorySource, configCheckContext,
                snapshotStore, properties.getCacheTtl(), Clock.systemUTC());
    }
}
