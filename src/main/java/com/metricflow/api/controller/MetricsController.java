package com.metricflow.api.controller;

import com.metricflow.api.model.Metric;
import com.metricflow.api.service.MetricsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "Metrics")
@RestController
@RequestMapping("/api/v1/metrics")
public class MetricsController {

    @Autowired
    private MetricsService metricsService;

    @Operation(summary = "List all metrics currently tracked for the account")
    @GetMapping
    public List<Metric> listMetrics() {
        return metricsService.findAll();
    }

    @Operation(summary = "Fetch a single metric by id")
    @GetMapping("/{id}")
    public Metric getMetric(@Parameter(description = "Metric id") @PathVariable Long id) {
        return metricsService.findById(id);
    }

    @Operation(summary = "Record a new metric value")
    @PostMapping
    public Metric createMetric(@RequestBody Metric metric) {
        return metricsService.save(metric);
    }
}
