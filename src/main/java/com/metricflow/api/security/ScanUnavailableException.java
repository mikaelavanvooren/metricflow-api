package com.metricflow.api.security;

/**
 * Raised when a scan cannot be produced at all, as opposed to producing a scan with no findings.
 * The distinction matters: an empty result must never be mistaken for a clean bill of health.
 */
public class ScanUnavailableException extends RuntimeException {

    public ScanUnavailableException(String message) {
        super(message);
    }

    public ScanUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
