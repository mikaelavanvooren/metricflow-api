package com.metricflow.api.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What changed between two scans. This is the answer to "did my fix actually land".
 */
public final class ScanDiff {

    private final String fromScanId;
    private final String fromScannedAt;
    private final String toScanId;
    private final String toScannedAt;
    private final List<SnapshotEntry> fixed;
    private final List<SnapshotEntry> introduced;
    private final List<SnapshotEntry> unchanged;

    private ScanDiff(String fromScanId, String fromScannedAt, String toScanId, String toScannedAt,
                     List<SnapshotEntry> fixed, List<SnapshotEntry> introduced,
                     List<SnapshotEntry> unchanged) {
        this.fromScanId = fromScanId;
        this.fromScannedAt = fromScannedAt;
        this.toScanId = toScanId;
        this.toScannedAt = toScannedAt;
        this.fixed = Collections.unmodifiableList(fixed);
        this.introduced = Collections.unmodifiableList(introduced);
        this.unchanged = Collections.unmodifiableList(unchanged);
    }

    /**
     * @param from the earlier scan, or null when there is no baseline yet, in which case every
     *             current finding counts as introduced
     */
    public static ScanDiff between(ScanSnapshot from, ScanSnapshot to) {
        Map<String, SnapshotEntry> before = index(from);
        Map<String, SnapshotEntry> after = index(to);

        List<SnapshotEntry> fixed = new ArrayList<>();
        for (Map.Entry<String, SnapshotEntry> entry : before.entrySet()) {
            if (!after.containsKey(entry.getKey())) {
                fixed.add(entry.getValue());
            }
        }
        List<SnapshotEntry> introduced = new ArrayList<>();
        List<SnapshotEntry> unchanged = new ArrayList<>();
        for (Map.Entry<String, SnapshotEntry> entry : after.entrySet()) {
            if (before.containsKey(entry.getKey())) {
                unchanged.add(entry.getValue());
            } else {
                introduced.add(entry.getValue());
            }
        }

        return new ScanDiff(
                from == null ? null : from.getScanId(),
                from == null ? null : from.getScannedAt(),
                to == null ? null : to.getScanId(),
                to == null ? null : to.getScannedAt(),
                fixed, introduced, unchanged);
    }

    private static Map<String, SnapshotEntry> index(ScanSnapshot snapshot) {
        Map<String, SnapshotEntry> byKey = new LinkedHashMap<>();
        if (snapshot != null) {
            for (SnapshotEntry entry : snapshot.getEntries()) {
                if (entry.getKey() != null) {
                    byKey.put(entry.getKey(), entry);
                }
            }
        }
        return byKey;
    }

    public String getFromScanId() {
        return fromScanId;
    }

    public String getFromScannedAt() {
        return fromScannedAt;
    }

    public String getToScanId() {
        return toScanId;
    }

    public String getToScannedAt() {
        return toScannedAt;
    }

    public List<SnapshotEntry> getFixed() {
        return fixed;
    }

    public List<SnapshotEntry> getIntroduced() {
        return introduced;
    }

    public List<SnapshotEntry> getUnchanged() {
        return unchanged;
    }

    public int getFixedCount() {
        return fixed.size();
    }

    public int getIntroducedCount() {
        return introduced.size();
    }

    public int getUnchangedCount() {
        return unchanged.size();
    }

    /** True when there is no earlier scan to compare against. */
    public boolean isBaseline() {
        return fromScanId == null;
    }
}
