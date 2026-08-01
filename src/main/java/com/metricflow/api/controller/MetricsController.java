package com.metricflow.api.controller;

import com.metricflow.api.model.Metric;
import com.metricflow.api.service.MetricsService;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Api(tags = "Metrics")
@RestController
@RequestMapping("/api/v1/metrics")
public class MetricsController {

    @Autowired
    private MetricsService metricsService;

    @ApiOperation("List all metrics currently tracked for the account")
    @GetMapping
    public List<Metric> listMetrics() {
        return metricsService.findAll();
    }

    @ApiOperation("Fetch a single metric by id")
    @GetMapping("/{id}")
    public Metric getMetric(@ApiParam("Metric id") @PathVariable Long id) {
        return metricsService.findById(id);
    }

    @ApiOperation("Record a new metric value")
    @PostMapping
    public Metric createMetric(@RequestBody Metric metric) {
        return metricsService.save(metric);
    }
}
