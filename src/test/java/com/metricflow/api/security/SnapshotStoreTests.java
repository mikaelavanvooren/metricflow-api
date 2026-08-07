package com.metricflow.api.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SnapshotStoreTests {

    private static ScanSnapshot snapshot(String id, String scannedAt, int vulnerabilities) {
        ScanSnapshot snapshot = new ScanSnapshot();
        snapshot.setScanId(id);
        snapshot.setScannedAt(scannedAt);
        snapshot.setTotalVulnerabilities(vulnerabilities);
        snapshot.setFailingConfigChecks(1);
        snapshot.setCountsBySeverity(Collections.singletonMap("HIGH", vulnerabilities));

        SnapshotEntry entry = new SnapshotEntry();
        entry.setKey("dependency:g:a@1.0|GHSA-" + id);
        entry.setKind(SnapshotEntry.KIND_DEPENDENCY);
        entry.setLabel("g:a 1.0");
        entry.setAdvisoryId("GHSA-" + id);
        entry.setSeverity("HIGH");
        snapshot.setEntries(Collections.singletonList(entry));
        return snapshot;
    }

    @Test
    void roundTripsASnapshot(@TempDir Path dir) {
        SnapshotStore store = new SnapshotStore(dir, 10);
        store.save(snapshot("100", "2026-08-06T10:00:00Z", 3));

        ScanSnapshot loaded = store.latest().orElseThrow(AssertionError::new);
        assertThat(loaded.getScanId()).isEqualTo("100");
        assertThat(loaded.getScannedAt()).isEqualTo("2026-08-06T10:00:00Z");
        assertThat(loaded.getTotalVulnerabilities()).isEqualTo(3);
        assertThat(loaded.getFailingConfigChecks()).isEqualTo(1);
        assertThat(loaded.getTotalFindings()).isEqualTo(4);
        assertThat(loaded.getCountsBySeverity()).containsEntry("HIGH", 3);
        assertThat(loaded.getEntries()).hasSize(1);
        assertThat(loaded.getEntries().get(0).getAdvisoryId()).isEqualTo("GHSA-100");
    }

    @Test
    void ordersHistoryOldestFirst(@TempDir Path dir) {
        SnapshotStore store = new SnapshotStore(dir, 10);
        store.save(snapshot("300", "2026-08-06T12:00:00Z", 1));
        store.save(snapshot("100", "2026-08-06T10:00:00Z", 3));
        store.save(snapshot("200", "2026-08-06T11:00:00Z", 2));

        assertThat(store.loadAll()).extracting(ScanSnapshot::getScanId)
                .containsExactly("100", "200", "300");
        assertThat(store.latest().orElseThrow(AssertionError::new).getScanId()).isEqualTo("300");
        assertThat(store.previous().orElseThrow(AssertionError::new).getScanId()).isEqualTo("200");
    }

    @Test
    void prunesOldestBeyondTheRetentionLimit(@TempDir Path dir) {
        SnapshotStore store = new SnapshotStore(dir, 2);
        store.save(snapshot("100", "2026-08-06T10:00:00Z", 3));
        store.save(snapshot("200", "2026-08-06T11:00:00Z", 2));
        store.save(snapshot("300", "2026-08-06T12:00:00Z", 1));

        assertThat(store.loadAll()).extracting(ScanSnapshot::getScanId).containsExactly("200", "300");
    }

    @Test
    void reportsNoHistoryWhenTheDirectoryDoesNotExist(@TempDir Path dir) {
        SnapshotStore store = new SnapshotStore(dir.resolve("not-created-yet"), 10);

        assertThat(store.loadAll()).isEmpty();
        assertThat(store.latest()).isEmpty();
        assertThat(store.previous()).isEmpty();
        assertThat(store.findById("100")).isEmpty();
    }

    @Test
    void previousRequiresTwoScans(@TempDir Path dir) {
        SnapshotStore store = new SnapshotStore(dir, 10);
        store.save(snapshot("100", "2026-08-06T10:00:00Z", 3));

        assertThat(store.previous()).isEmpty();
    }

    @Test
    void findsBySpecificScanId(@TempDir Path dir) {
        SnapshotStore store = new SnapshotStore(dir, 10);
        store.save(snapshot("100", "2026-08-06T10:00:00Z", 3));
        store.save(snapshot("200", "2026-08-06T11:00:00Z", 2));

        assertThat(store.findById("100")).isPresent();
        assertThat(store.findById("999")).isEmpty();
        assertThat(store.findById(null)).isEmpty();
    }

    /**
     * History is a convenience, not the scan itself, so a corrupt or partially written file must be
     * skipped rather than take down every subsequent read.
     */
    @Test
    void skipsUnreadableSnapshots(@TempDir Path dir) throws IOException {
        SnapshotStore store = new SnapshotStore(dir, 10);
        store.save(snapshot("100", "2026-08-06T10:00:00Z", 3));
        Files.write(dir.resolve("scan-broken.json"), "{ this is not json".getBytes("UTF-8"));

        List<ScanSnapshot> loaded = store.loadAll();
        assertThat(loaded).extracting(ScanSnapshot::getScanId).containsExactly("100");
    }

    /** Snapshots may be read back after an upgrade, so newer fields must not break older readers. */
    @Test
    void ignoresUnknownFields(@TempDir Path dir) throws IOException {
        Files.createDirectories(dir);
        Files.write(dir.resolve("scan-100.json"),
                ("{\"scanId\":\"100\",\"scannedAt\":\"2026-08-06T10:00:00Z\","
                        + "\"totalVulnerabilities\":2,\"somethingAddedLater\":true}").getBytes("UTF-8"));

        SnapshotStore store = new SnapshotStore(dir, 10);
        assertThat(store.latest().orElseThrow(AssertionError::new).getTotalVulnerabilities()).isEqualTo(2);
    }

    @Test
    void createsTheDirectoryOnFirstSave(@TempDir Path dir) {
        Path nested = dir.resolve("nested/security-snapshots");
        new SnapshotStore(nested, 10).save(snapshot("100", "2026-08-06T10:00:00Z", 1));

        assertThat(nested).exists();
        assertThat(new SnapshotStore(nested, 10).loadAll()).hasSize(1);
    }
}
