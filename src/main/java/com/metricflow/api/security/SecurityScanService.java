package com.metricflow.api.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Produces vulnerability scans and keeps their history.
 *
 * <p>A scan combines two independent sources: published advisories for the resolved dependency
 * tree, and configuration checks over the running application's own settings.
 */
public class SecurityScanService {

    private static final Logger log = LoggerFactory.getLogger(SecurityScanService.class);
    private static final String SOURCE = "osv.dev";

    private final DependencySource inventory;
    private final AdvisorySource advisorySource;
    private final ConfigCheckContext configContext;
    private final SnapshotStore snapshotStore;
    private final Duration cacheTtl;
    private final Clock clock;

    private volatile SecurityScanReport cachedReport;
    private volatile Instant cachedAt;

    public SecurityScanService(DependencySource inventory,
                               AdvisorySource advisorySource,
                               ConfigCheckContext configContext,
                               SnapshotStore snapshotStore,
                               Duration cacheTtl,
                               Clock clock) {
        this.inventory = inventory;
        this.advisorySource = advisorySource;
        this.configContext = configContext;
        this.snapshotStore = snapshotStore;
        this.cacheTtl = cacheTtl == null ? Duration.ZERO : cacheTtl;
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    /**
     * @param refresh when true, ignores the cached result and queries OSV again
     * @throws ScanUnavailableException when the dependency inventory or OSV cannot be reached
     */
    public synchronized SecurityScanReport scan(boolean refresh) {
        SecurityScanReport cached = cachedReport;
        if (!refresh && cached != null && cachedAt != null
                && Duration.between(cachedAt, clock.instant()).compareTo(cacheTtl) < 0) {
            return cached;
        }
        SecurityScanReport report = runScan();
        cachedReport = report;
        cachedAt = clock.instant();
        snapshotStore.save(ScanSnapshot.from(report));
        return report;
    }

    public SecurityScanReport scan(boolean refresh, Severity minSeverity) {
        return scan(refresh).filtered(minSeverity);
    }

    private SecurityScanReport runScan() {
        List<DependencyCoordinate> dependencies = inventory.load().orElseThrow(() ->
                new ScanUnavailableException(
                        "Dependency inventory " + DependencyInventory.DEFAULT_RESOURCE + " is missing "
                                + "from the classpath. Run the Maven build so the resolved dependency "
                                + "list is recorded, then restart."));

        Map<DependencyCoordinate, List<Vulnerability>> advisories;
        try {
            advisories = advisorySource.findVulnerabilities(dependencies);
        } catch (OsvClient.OsvUnavailableException e) {
            throw new ScanUnavailableException(
                    "The OSV.dev vulnerability database could not be reached: " + e.getMessage(), e);
        }

        List<VulnerableDependency> findings = new ArrayList<>();
        advisories.forEach((dependency, vulnerabilities) ->
                findings.add(new VulnerableDependency(dependency, vulnerabilities)));

        List<ConfigFinding> configFindings = ConfigChecks.evaluateAll(configContext);

        Instant now = clock.instant();
        SecurityScanReport report = new SecurityScanReport(
                scanId(now),
                DateTimeFormatter.ISO_INSTANT.format(now),
                SOURCE,
                dependencies.size(),
                findings,
                configFindings);

        log.info("Security scan {}: {} dependencies, {} advisories across {} dependencies, {} failing checks",
                report.getScanId(), report.getDependenciesScanned(), report.getTotalVulnerabilities(),
                report.getVulnerableDependencies(), report.getFailingConfigChecks());
        return report;
    }

    /** Scan history, oldest first. */
    public List<ScanSnapshot> history() {
        return snapshotStore.loadAll();
    }

    /**
     * Compares two scans. With no arguments this is the previous scan against the latest, which is
     * the question worth asking after a fix.
     *
     * @throws ScanUnavailableException when no scan has been recorded yet
     */
    public ScanDiff diff(String fromScanId, String toScanId) {
        ScanSnapshot to = resolve(toScanId, snapshotStore::latest).orElseThrow(() ->
                new ScanUnavailableException(
                        "No scan has been recorded yet. Call /api/v1/security/scan first."));

        ScanSnapshot from;
        if (fromScanId == null || fromScanId.trim().isEmpty()) {
            // Default baseline is the scan before the latest, not the scan before "to".
            from = snapshotStore.previous().orElse(null);
            if (from != null && from.getScanId() != null && from.getScanId().equals(to.getScanId())) {
                from = null;
            }
        } else {
            from = snapshotStore.findById(fromScanId).orElseThrow(() ->
                    new ScanUnavailableException("No scan recorded with id " + fromScanId));
        }
        return ScanDiff.between(from, to);
    }

    private Optional<ScanSnapshot> resolve(String scanId, java.util.function.Supplier<Optional<ScanSnapshot>> fallback) {
        if (scanId == null || scanId.trim().isEmpty()) {
            return fallback.get();
        }
        return snapshotStore.findById(scanId);
    }

    private String scanId(Instant instant) {
        return Long.toString(instant.toEpochMilli());
    }
}
