package com.metricflow.api.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.mock.env.MockEnvironment;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecurityScanServiceTests {

    private static final DependencyCoordinate SPRING_BOOT =
            new DependencyCoordinate("org.springframework.boot", "spring-boot", "2.7.18", "compile");
    private static final DependencyCoordinate H2 =
            new DependencyCoordinate("com.h2database", "h2", "2.1.214", "runtime");

    private MutableClock clock;
    private StubOsvClient osvClient;
    private SnapshotStore store;

    @BeforeEach
    void setUp(@TempDir Path dir) {
        clock = new MutableClock(Instant.parse("2026-08-06T10:00:00Z"));
        osvClient = new StubOsvClient();
        store = new SnapshotStore(dir, 20);
    }

    private SecurityScanService service(List<DependencyCoordinate> dependencies, Duration ttl) {
        return new SecurityScanService(
                new StubInventory(dependencies),
                osvClient,
                configContext(),
                store,
                ttl,
                clock);
    }

    private static ConfigCheckContext configContext() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("spring.jpa.hibernate.ddl-auto", "update")
                .withProperty("springfox.documentation.swagger-ui.enabled", "true");
        return new ConfigCheckContext(environment, "2.7.18", 55, "11.0.22", className -> false);
    }

    private static Vulnerability vulnerability(String id, Severity severity, String... fixedVersions) {
        return new Vulnerability(id, Collections.emptyList(), severity, null, null, id + " summary",
                Arrays.asList(fixedVersions), Collections.emptyList(), null, null);
    }

    @Test
    void aggregatesAdvisoriesAndConfigurationFindings() {
        osvClient.respond(SPRING_BOOT, vulnerability("GHSA-a", Severity.HIGH, "3.3.11"));
        osvClient.respond(H2, vulnerability("GHSA-b", Severity.CRITICAL), vulnerability("GHSA-c", Severity.LOW));

        SecurityScanReport report = service(Arrays.asList(SPRING_BOOT, H2), Duration.ZERO).scan(false);

        assertThat(report.getDependenciesScanned()).isEqualTo(2);
        assertThat(report.getVulnerableDependencies()).isEqualTo(2);
        assertThat(report.getTotalVulnerabilities()).isEqualTo(3);
        assertThat(report.getSource()).isEqualTo("osv.dev");
        assertThat(report.getScannedAt()).isEqualTo("2026-08-06T10:00:00Z");
        // All six checks fail for this configuration except the H2 console, which is not enabled.
        assertThat(report.getFailingConfigChecks()).isEqualTo(5);
        assertThat(report.getTotalFindings()).isEqualTo(8);
        assertThat(report.getHighestSeverity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void countsAdvisoriesAndFailingChecksBySeverity() {
        osvClient.respond(SPRING_BOOT, vulnerability("GHSA-a", Severity.HIGH));
        osvClient.respond(H2, vulnerability("GHSA-b", Severity.CRITICAL), vulnerability("GHSA-c", Severity.LOW));

        Map<Severity, Integer> counts =
                service(Arrays.asList(SPRING_BOOT, H2), Duration.ZERO).scan(false).getCountsBySeverity();

        assertThat(counts.get(Severity.CRITICAL)).isEqualTo(1);
        // One HIGH advisory plus the two HIGH configuration failures.
        assertThat(counts.get(Severity.HIGH)).isEqualTo(3);
        assertThat(counts.get(Severity.MEDIUM)).isEqualTo(3);
        assertThat(counts.get(Severity.LOW)).isEqualTo(1);
    }

    @Test
    void ordersDependenciesBySeverityThenName() {
        osvClient.respond(SPRING_BOOT, vulnerability("GHSA-a", Severity.LOW));
        osvClient.respond(H2, vulnerability("GHSA-b", Severity.CRITICAL));

        SecurityScanReport report = service(Arrays.asList(SPRING_BOOT, H2), Duration.ZERO).scan(false);

        assertThat(report.getDependencyFindings()).extracting(f -> f.getDependency().getArtifactId())
                .containsExactly("h2", "spring-boot");
    }

    @Test
    void filtersByMinimumSeverity() {
        osvClient.respond(SPRING_BOOT, vulnerability("GHSA-a", Severity.HIGH));
        osvClient.respond(H2, vulnerability("GHSA-b", Severity.LOW));

        SecurityScanReport filtered =
                service(Arrays.asList(SPRING_BOOT, H2), Duration.ZERO).scan(false, Severity.HIGH);

        assertThat(filtered.getTotalVulnerabilities()).isEqualTo(1);
        assertThat(filtered.getDependencyFindings()).hasSize(1);
        assertThat(filtered.getDependencyFindings().get(0).getVulnerabilities())
                .extracting(Vulnerability::getId).containsExactly("GHSA-a");
        // MEDIUM configuration failures drop out, the two HIGH ones remain.
        assertThat(filtered.getFailingConfigChecks()).isEqualTo(2);
    }

    /** Passing checks stay visible under a filter so a fix reads as green rather than as absent. */
    @Test
    void keepsPassingChecksWhenFiltering() {
        SecurityScanReport filtered =
                service(Collections.singletonList(SPRING_BOOT), Duration.ZERO).scan(false, Severity.CRITICAL);

        assertThat(filtered.getConfigFindings()).filteredOn(ConfigFinding::isPassing).isNotEmpty();
    }

    @Test
    void servesTheCachedScanUntilTheTtlExpires() {
        osvClient.respond(SPRING_BOOT, vulnerability("GHSA-a", Severity.HIGH));
        SecurityScanService service = service(Collections.singletonList(SPRING_BOOT), Duration.ofMinutes(15));

        service.scan(false);
        service.scan(false);
        assertThat(osvClient.getCallCount()).isEqualTo(1);

        clock.advance(Duration.ofMinutes(16));
        service.scan(false);
        assertThat(osvClient.getCallCount()).isEqualTo(2);
    }

    @Test
    void refreshBypassesTheCache() {
        osvClient.respond(SPRING_BOOT, vulnerability("GHSA-a", Severity.HIGH));
        SecurityScanService service = service(Collections.singletonList(SPRING_BOOT), Duration.ofMinutes(15));

        service.scan(false);
        service.scan(true);

        assertThat(osvClient.getCallCount()).isEqualTo(2);
    }

    @Test
    void recordsEveryScanInHistory() {
        osvClient.respond(SPRING_BOOT, vulnerability("GHSA-a", Severity.HIGH));
        SecurityScanService service = service(Collections.singletonList(SPRING_BOOT), Duration.ZERO);

        service.scan(false);
        clock.advance(Duration.ofMinutes(5));
        service.scan(false);

        assertThat(service.history()).hasSize(2);
    }

    /** The scenario this feature exists for: upgrade a dependency and confirm the finding cleared. */
    @Test
    void reportsAnUpgradedDependencyAsFixed() {
        osvClient.respond(SPRING_BOOT, vulnerability("GHSA-a", Severity.HIGH, "3.3.11"));
        service(Collections.singletonList(SPRING_BOOT), Duration.ZERO).scan(false);

        clock.advance(Duration.ofMinutes(5));
        DependencyCoordinate upgraded =
                new DependencyCoordinate("org.springframework.boot", "spring-boot", "3.3.11", "compile");
        osvClient.clear();
        SecurityScanService afterUpgrade = service(Collections.singletonList(upgraded), Duration.ZERO);
        afterUpgrade.scan(false);

        ScanDiff diff = afterUpgrade.diff(null, null);
        assertThat(diff.isBaseline()).isFalse();
        assertThat(diff.getFixed()).extracting(SnapshotEntry::getAdvisoryId).containsExactly("GHSA-a");
        assertThat(diff.getIntroduced()).isEmpty();
        // The configuration findings are unchanged across both scans.
        assertThat(diff.getUnchangedCount()).isEqualTo(5);
    }

    @Test
    void reportsANewAdvisoryAsIntroduced() {
        SecurityScanService service = service(Collections.singletonList(SPRING_BOOT), Duration.ZERO);
        service.scan(false);

        clock.advance(Duration.ofMinutes(5));
        osvClient.respond(SPRING_BOOT, vulnerability("GHSA-new", Severity.CRITICAL));
        service.scan(true);

        ScanDiff diff = service.diff(null, null);
        assertThat(diff.getIntroduced()).extracting(SnapshotEntry::getAdvisoryId).containsExactly("GHSA-new");
        assertThat(diff.getFixed()).isEmpty();
    }

    @Test
    void treatsTheFirstScanAsABaseline() {
        osvClient.respond(SPRING_BOOT, vulnerability("GHSA-a", Severity.HIGH));
        SecurityScanService service = service(Collections.singletonList(SPRING_BOOT), Duration.ZERO);
        service.scan(false);

        ScanDiff diff = service.diff(null, null);

        assertThat(diff.isBaseline()).isTrue();
        assertThat(diff.getFixed()).isEmpty();
        assertThat(diff.getIntroducedCount()).isEqualTo(6);
    }

    @Test
    void diffsTwoExplicitScans() {
        osvClient.respond(SPRING_BOOT, vulnerability("GHSA-a", Severity.HIGH));
        SecurityScanService service = service(Collections.singletonList(SPRING_BOOT), Duration.ZERO);
        SecurityScanReport first = service.scan(false);

        clock.advance(Duration.ofMinutes(5));
        osvClient.clear();
        SecurityScanReport second = service.scan(true);

        ScanDiff diff = service.diff(first.getScanId(), second.getScanId());
        assertThat(diff.getFixed()).extracting(SnapshotEntry::getAdvisoryId).containsExactly("GHSA-a");
    }

    @Test
    void rejectsAnUnknownBaselineScanId() {
        osvClient.respond(SPRING_BOOT, vulnerability("GHSA-a", Severity.HIGH));
        SecurityScanService service = service(Collections.singletonList(SPRING_BOOT), Duration.ZERO);
        service.scan(false);

        assertThatThrownBy(() -> service.diff("no-such-scan", null))
                .isInstanceOf(ScanUnavailableException.class)
                .hasMessageContaining("no-such-scan");
    }

    @Test
    void reportsUnavailableWhenNoScanHasBeenRecorded() {
        assertThatThrownBy(() -> service(Collections.singletonList(SPRING_BOOT), Duration.ZERO).diff(null, null))
                .isInstanceOf(ScanUnavailableException.class)
                .hasMessageContaining("No scan has been recorded");
    }

    /** An absent inventory must never be reported as a clean scan. */
    @Test
    void reportsUnavailableWhenTheDependencyInventoryIsMissing() {
        SecurityScanService service = new SecurityScanService(
                new StubInventory(null), osvClient, configContext(), store, Duration.ZERO, clock);

        assertThatThrownBy(() -> service.scan(false))
                .isInstanceOf(ScanUnavailableException.class)
                .hasMessageContaining("metricflow-dependencies.txt");
    }

    @Test
    void reportsUnavailableWhenTheAdvisoryDatabaseCannotBeReached() {
        osvClient.failWith(new OsvClient.OsvUnavailableException("connection reset", new RuntimeException()));

        assertThatThrownBy(() -> service(Collections.singletonList(SPRING_BOOT), Duration.ZERO).scan(false))
                .isInstanceOf(ScanUnavailableException.class)
                .hasMessageContaining("OSV.dev");
    }

    @Test
    void producesAScanWhenNothingIsVulnerable() {
        SecurityScanReport report = service(Arrays.asList(SPRING_BOOT, H2), Duration.ZERO).scan(false);

        assertThat(report.getDependenciesScanned()).isEqualTo(2);
        assertThat(report.getVulnerableDependencies()).isZero();
        assertThat(report.getTotalVulnerabilities()).isZero();
        assertThat(report.getDependencyFindings()).isEmpty();
    }

    private static final class StubInventory implements DependencySource {
        private final List<DependencyCoordinate> dependencies;

        StubInventory(List<DependencyCoordinate> dependencies) {
            this.dependencies = dependencies;
        }

        @Override
        public Optional<List<DependencyCoordinate>> load() {
            return Optional.ofNullable(dependencies);
        }
    }

    private static final class StubOsvClient implements AdvisorySource {
        private final Map<DependencyCoordinate, List<Vulnerability>> responses = new LinkedHashMap<>();
        private RuntimeException failure;
        private int callCount;

        void respond(DependencyCoordinate dependency, Vulnerability... vulnerabilities) {
            responses.put(dependency, new ArrayList<>(Arrays.asList(vulnerabilities)));
        }

        void clear() {
            responses.clear();
        }

        void failWith(RuntimeException e) {
            this.failure = e;
        }

        int getCallCount() {
            return callCount;
        }

        @Override
        public Map<DependencyCoordinate, List<Vulnerability>> findVulnerabilities(
                List<DependencyCoordinate> dependencies) {
            callCount++;
            if (failure != null) {
                throw failure;
            }
            Map<DependencyCoordinate, List<Vulnerability>> found = new LinkedHashMap<>();
            for (DependencyCoordinate dependency : dependencies) {
                List<Vulnerability> vulnerabilities = responses.get(dependency);
                if (vulnerabilities != null && !vulnerabilities.isEmpty()) {
                    found.put(dependency, vulnerabilities);
                }
            }
            return found;
        }
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration amount) {
            now = now.plus(amount);
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
