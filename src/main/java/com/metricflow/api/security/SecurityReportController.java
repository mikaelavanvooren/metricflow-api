package com.metricflow.api.security;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reports the vulnerabilities present in this deployment: published advisories affecting the
 * resolved dependency tree, plus configuration checks.
 */
@Api(tags = "Security")
@RestController
@RequestMapping("/api/v1/security")
@ConditionalOnProperty(prefix = "metricflow.security", name = "enabled", havingValue = "true")
public class SecurityReportController {

    private final SecurityScanService scanService;

    public SecurityReportController(SecurityScanService scanService) {
        this.scanService = scanService;
    }

    @ApiOperation(value = "Full vulnerability scan",
            notes = "Advisories for every resolved dependency plus the configuration checks. "
                    + "Results are cached; pass refresh=true to query the advisory database again.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Scan completed"),
            @ApiResponse(code = 400, message = "Unrecognised minSeverity value"),
            @ApiResponse(code = 503, message = "Scan could not be produced")
    })
    @GetMapping("/scan")
    public SecurityScanReport scan(
            @ApiParam(value = "Lowest severity to include", allowableValues = "LOW,MEDIUM,HIGH,CRITICAL")
            @RequestParam(required = false) String minSeverity,
            @ApiParam("Bypass the cached result and rescan")
            @RequestParam(defaultValue = "false") boolean refresh) {
        return scanService.scan(refresh, parseSeverity(minSeverity));
    }

    @ApiOperation(value = "Scan totals only",
            notes = "Counts without the finding detail, for badges and health checks.")
    @GetMapping("/summary")
    public Map<String, Object> summary() {
        SecurityScanReport report = scanService.scan(false);
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("scanId", report.getScanId());
        summary.put("scannedAt", report.getScannedAt());
        summary.put("source", report.getSource());
        summary.put("dependenciesScanned", report.getDependenciesScanned());
        summary.put("vulnerableDependencies", report.getVulnerableDependencies());
        summary.put("totalVulnerabilities", report.getTotalVulnerabilities());
        summary.put("failingConfigChecks", report.getFailingConfigChecks());
        summary.put("totalFindings", report.getTotalFindings());
        summary.put("highestSeverity", report.getHighestSeverity());
        summary.put("countsBySeverity", report.getCountsBySeverity());
        return summary;
    }

    @ApiOperation(value = "Scan history", notes = "Recorded scans, oldest first.")
    @GetMapping("/history")
    public List<ScanSnapshot> history() {
        return scanService.history();
    }

    @ApiOperation(value = "Compare two scans",
            notes = "Defaults to the previous scan against the latest, which shows what a fix "
                    + "removed and what a change introduced.")
    @ApiResponses({
            @ApiResponse(code = 200, message = "Diff computed"),
            @ApiResponse(code = 503, message = "Not enough scan history to compare")
    })
    @GetMapping("/diff")
    public ScanDiff diff(
            @ApiParam("Baseline scan id; defaults to the scan before the latest")
            @RequestParam(required = false) String from,
            @ApiParam("Comparison scan id; defaults to the latest scan")
            @RequestParam(required = false) String to) {
        return scanService.diff(from, to);
    }

    private Severity parseSeverity(String value) {
        if (value == null || value.trim().isEmpty()) {
            return Severity.UNKNOWN;
        }
        try {
            return Severity.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unrecognised minSeverity '" + value
                    + "'. Expected one of LOW, MEDIUM, HIGH, CRITICAL.");
        }
    }

    /**
     * A scan that cannot be produced is reported as unavailable rather than as an empty result, so
     * an absent inventory or an unreachable advisory database is never mistaken for "no findings".
     */
    @ExceptionHandler(ScanUnavailableException.class)
    @ResponseStatus(HttpStatus.SERVICE_UNAVAILABLE)
    public Map<String, Object> handleScanUnavailable(ScanUnavailableException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", HttpStatus.SERVICE_UNAVAILABLE.value());
        body.put("error", "Scan unavailable");
        body.put("message", e.getMessage());
        return body;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Map<String, Object> handleBadRequest(IllegalArgumentException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", HttpStatus.BAD_REQUEST.value());
        body.put("error", "Bad request");
        body.put("message", e.getMessage());
        return body;
    }
}
