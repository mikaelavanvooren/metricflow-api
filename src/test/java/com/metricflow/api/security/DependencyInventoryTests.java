package com.metricflow.api.security;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DependencyInventoryTests {

    @Test
    void parsesStandardDependencyListOutput() {
        List<DependencyCoordinate> parsed = DependencyInventory.parse(Arrays.asList(
                "",
                "The following files have been resolved:",
                "   org.springframework.boot:spring-boot:jar:2.7.18:compile",
                "   com.h2database:h2:jar:2.1.214:runtime"));

        assertThat(parsed).hasSize(2);
        assertThat(parsed.get(0).getGroupId()).isEqualTo("com.h2database");
        assertThat(parsed.get(0).getArtifactId()).isEqualTo("h2");
        assertThat(parsed.get(0).getVersion()).isEqualTo("2.1.214");
        assertThat(parsed.get(0).getScope()).isEqualTo("runtime");
        assertThat(parsed.get(1).getMavenName()).isEqualTo("org.springframework.boot:spring-boot");
    }

    /**
     * Maven decorates the list with ANSI colour codes and a Java module descriptor when it detects a
     * colour-capable terminal, so the same build produces different bytes depending on how it was
     * invoked. Both forms have to parse identically.
     */
    @Test
    void stripsAnsiCodesAndModuleDescriptors() {
        List<DependencyCoordinate> parsed = DependencyInventory.parse(Arrays.asList(
                "   ch.qos.logback:logback-classic:jar:1.2.12:compile\u001B[36m -- module logback.classic\u001B[0;1;33m (auto)\u001B[m",
                "   com.fasterxml.jackson.core:jackson-databind:jar:2.13.5:compile\u001B[36m -- module com.fasterxml.jackson.databind\u001B[m"));

        assertThat(parsed).extracting(DependencyCoordinate::getKey).containsExactly(
                "ch.qos.logback:logback-classic@1.2.12",
                "com.fasterxml.jackson.core:jackson-databind@2.13.5");
    }

    @Test
    void handlesClassifiedArtifacts() {
        List<DependencyCoordinate> parsed = DependencyInventory.parse(Collections.singletonList(
                "   org.example:native-lib:jar:linux-x86_64:1.4.2:compile"));

        assertThat(parsed).hasSize(1);
        assertThat(parsed.get(0).getVersion()).isEqualTo("1.4.2");
        assertThat(parsed.get(0).getScope()).isEqualTo("compile");
    }

    @Test
    void skipsHeadersBlanksAndMalformedLines() {
        List<DependencyCoordinate> parsed = DependencyInventory.parse(Arrays.asList(
                null,
                "",
                "   ",
                "The following files have been resolved:",
                "none",
                "not:enough:parts",
                "way:too:many:parts:to:be:valid:here:really",
                "   bad group:artifact:jar:1.0:compile",
                "   org.example:good:jar:1.0.0:compile"));

        assertThat(parsed).extracting(DependencyCoordinate::getMavenName).containsExactly("org.example:good");
    }

    @Test
    void deduplicatesRepeatedEntries() {
        List<DependencyCoordinate> parsed = DependencyInventory.parse(Arrays.asList(
                "   org.example:dup:jar:1.0.0:compile",
                "   org.example:dup:jar:1.0.0:compile"));

        assertThat(parsed).hasSize(1);
    }

    @Test
    void reportsMissingInventoryAsEmptyRatherThanAsNoDependencies() {
        assertThat(new DependencyInventory("META-INF/does-not-exist.txt").load()).isEmpty();
    }

    /**
     * The build records this file, so its absence during a test run would mean the packaging step
     * silently stopped working and every scan would come back empty.
     */
    @Test
    void loadsTheInventoryProducedByTheBuild() {
        List<DependencyCoordinate> loaded = new DependencyInventory().load()
                .orElseThrow(() -> new AssertionError(
                        "the build did not write " + DependencyInventory.DEFAULT_RESOURCE));

        assertThat(loaded).isNotEmpty();
        assertThat(loaded).extracting(DependencyCoordinate::getMavenName)
                .contains("org.springframework.boot:spring-boot",
                        "org.springdoc:springdoc-openapi-starter-webmvc-ui");
    }

    @Test
    void buildsPackageUrls() {
        DependencyCoordinate coordinate =
                new DependencyCoordinate("org.springframework.boot", "spring-boot", "2.7.18", "compile");

        assertThat(coordinate.getPurl()).isEqualTo("pkg:maven/org.springframework.boot/spring-boot@2.7.18");
        assertThat(coordinate.getKey()).isEqualTo("org.springframework.boot:spring-boot@2.7.18");
    }

    @Test
    void defaultsAMissingScopeToCompile() {
        assertThat(new DependencyCoordinate("g", "a", "1.0", null).getScope()).isEqualTo("compile");
    }
}
