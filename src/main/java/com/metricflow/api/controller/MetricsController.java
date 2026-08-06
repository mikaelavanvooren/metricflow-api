package com.metricflow.api.controller;

import com.metricflow.api.model.Metric;
import com.metricflow.api.service.MetricsService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
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
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Metric found"),
            @ApiResponse(responseCode = "404", description = "Metric not found")
    })
    @GetMapping("/{id}")
    public Metric getMetric(@Parameter(description = "Metric id") @PathVariable Long id) {
        Metric metric = metricsService.findById(id);
        if (metric == null) {
            throw new ResourceNotFoundException("No metric with id " + id);
        }
        return metric;
    }

    @Operation(summary = "Record a new metric value")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Metric recorded"),
            @ApiResponse(responseCode = "400", description = "Invalid metric payload")
    })
    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping
    public Metric createMetric(@RequestBody Metric metric) {
        return metricsService.save(metric);
    }
}
