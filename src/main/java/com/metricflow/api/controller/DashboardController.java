package com.metricflow.api.controller;

import com.metricflow.api.model.Dashboard;
import com.metricflow.api.service.DashboardService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Tag(name = "Dashboards")
@RestController
@RequestMapping("/api/v1/dashboards")
public class DashboardController {

    @Autowired
    private DashboardService dashboardService;

    @Operation(summary = "List dashboards visible to the current user")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Dashboards returned successfully"),
            @ApiResponse(responseCode = "401", description = "Not authenticated")
    })
    @GetMapping
    public List<Dashboard> listDashboards(
            @Parameter(description = "Filter by owner email") @RequestParam(required = false) String owner,
            @Parameter(description = "Only return shared dashboards") @RequestParam(defaultValue = "false") boolean sharedOnly) {
        return dashboardService.find(owner, sharedOnly);
    }

    @Operation(summary = "Create a new dashboard")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Dashboard created"),
            @ApiResponse(responseCode = "400", description = "Invalid dashboard payload")
    })
    @PostMapping
    public Dashboard createDashboard(@RequestBody Dashboard dashboard) {
        return dashboardService.save(dashboard);
    }

    @Operation(summary = "Delete a dashboard", description = "Only the owner may delete a dashboard")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Dashboard deleted"),
            @ApiResponse(responseCode = "403", description = "Not the dashboard owner"),
            @ApiResponse(responseCode = "404", description = "Dashboard not found")
    })
    @DeleteMapping("/{id}")
    public void deleteDashboard(@Parameter(description = "Dashboard id") @PathVariable Long id) {
        dashboardService.delete(id);
    }
}
