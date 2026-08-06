package com.metricflow.api.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/**
 * Keeps scan history on disk.
 *
 * <p>File-backed rather than in the H2 in-memory database because the classpath only changes across
 * a restart: an upgraded dependency is invisible until the application is rebuilt and relaunched,
 * which is precisely when in-memory history would be lost, taking the "before" side of the diff
 * with it.
 */
public class SnapshotStore {

    private static final Logger log = LoggerFactory.getLogger(SnapshotStore.class);
    private static final String PREFIX = "scan-";
    private static final String SUFFIX = ".json";

    // Jackson 3 mappers are immutable, so features are selected on the builder rather than switched
    // on afterwards.
    private final ObjectMapper mapper =
            JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build();
    private final Path directory;
    private final int historyLimit;

    public SnapshotStore(Path directory, int historyLimit) {
        this.directory = directory;
        this.historyLimit = Math.max(1, historyLimit);
    }

    public Path getDirectory() {
        return directory;
    }

    /**
     * Writes the snapshot and prunes the oldest beyond the retention limit. Persistence failures are
     * logged and swallowed: losing history is not a reason to fail the scan the caller asked for.
     */
    public void save(ScanSnapshot snapshot) {
        try {
            Files.createDirectories(directory);
            Path target = directory.resolve(PREFIX + snapshot.getScanId() + SUFFIX);
            mapper.writeValue(target.toFile(), snapshot);
            prune();
        } catch (IOException | JacksonException e) {
            log.warn("Could not persist security scan snapshot: {}", e.getMessage());
        }
    }

    /** Snapshots ordered oldest first. */
    public List<ScanSnapshot> loadAll() {
        if (!Files.isDirectory(directory)) {
            return Collections.emptyList();
        }
        List<ScanSnapshot> snapshots = new ArrayList<>();
        for (Path file : listFiles()) {
            try {
                snapshots.add(mapper.readValue(file.toFile(), ScanSnapshot.class));
            } catch (JacksonException e) {
                log.warn("Ignoring unreadable snapshot {}: {}", file.getFileName(), e.getMessage());
            }
        }
        snapshots.sort(Comparator.comparing(
                ScanSnapshot::getScannedAt, Comparator.nullsFirst(Comparator.naturalOrder())));
        return snapshots;
    }

    public Optional<ScanSnapshot> findById(String scanId) {
        if (scanId == null) {
            return Optional.empty();
        }
        for (ScanSnapshot snapshot : loadAll()) {
            if (scanId.equals(snapshot.getScanId())) {
                return Optional.of(snapshot);
            }
        }
        return Optional.empty();
    }

    public Optional<ScanSnapshot> latest() {
        List<ScanSnapshot> all = loadAll();
        return all.isEmpty() ? Optional.empty() : Optional.of(all.get(all.size() - 1));
    }

    /** The scan before the most recent one, which is the default baseline for a diff. */
    public Optional<ScanSnapshot> previous() {
        List<ScanSnapshot> all = loadAll();
        return all.size() < 2 ? Optional.empty() : Optional.of(all.get(all.size() - 2));
    }

    private void prune() {
        List<ScanSnapshot> all = loadAll();
        if (all.size() <= historyLimit) {
            return;
        }
        for (ScanSnapshot stale : all.subList(0, all.size() - historyLimit)) {
            Path file = directory.resolve(PREFIX + stale.getScanId() + SUFFIX);
            try {
                Files.deleteIfExists(file);
            } catch (IOException e) {
                log.warn("Could not prune snapshot {}: {}", file.getFileName(), e.getMessage());
            }
        }
    }

    private List<Path> listFiles() {
        List<Path> files = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory, PREFIX + "*" + SUFFIX)) {
            for (Path file : stream) {
                files.add(file);
            }
        } catch (IOException e) {
            log.warn("Could not list snapshot directory {}: {}", directory, e.getMessage());
        }
        return files;
    }
}
