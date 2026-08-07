package com.metricflow.api.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "metricflow.security")
public class SecurityProperties {

    /**
     * Whether the vulnerability endpoints are exposed. Off by default: an enumeration of this
     * application's own unpatched advisories is reconnaissance material, and there is no
     * authentication in front of it.
     */
    private boolean enabled = false;

    /**
     * Where scan history is kept. Outside target/ on purpose, since mvn clean would otherwise
     * delete the baseline needed to show what a fix changed.
     */
    private String snapshotDir = ".metricflow/security-snapshots";

    /** Number of scans retained for history and diffing. */
    private int historyLimit = 20;

    private String osvBaseUrl = "https://api.osv.dev";

    /** Parallel advisory lookups. OSV rate limits aggressive clients. */
    private int fetchConcurrency = 8;

    private Duration connectTimeout = Duration.ofSeconds(5);

    private Duration readTimeout = Duration.ofSeconds(20);

    /** How long a completed scan is served before a rescan is triggered. */
    private Duration cacheTtl = Duration.ofMinutes(15);

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getSnapshotDir() {
        return snapshotDir;
    }

    public void setSnapshotDir(String snapshotDir) {
        this.snapshotDir = snapshotDir;
    }

    public int getHistoryLimit() {
        return historyLimit;
    }

    public void setHistoryLimit(int historyLimit) {
        this.historyLimit = historyLimit;
    }

    public String getOsvBaseUrl() {
        return osvBaseUrl;
    }

    public void setOsvBaseUrl(String osvBaseUrl) {
        this.osvBaseUrl = osvBaseUrl;
    }

    public int getFetchConcurrency() {
        return fetchConcurrency;
    }

    public void setFetchConcurrency(int fetchConcurrency) {
        this.fetchConcurrency = fetchConcurrency;
    }

    public Duration getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(Duration connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public Duration getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(Duration readTimeout) {
        this.readTimeout = readTimeout;
    }

    public Duration getCacheTtl() {
        return cacheTtl;
    }

    public void setCacheTtl(Duration cacheTtl) {
        this.cacheTtl = cacheTtl;
    }
}
