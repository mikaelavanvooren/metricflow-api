package com.metricflow.api.controller;

import com.metricflow.api.model.Dashboard;
import com.metricflow.api.service.DashboardService;
import io.swagger.annotations.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Api(tags = "Dashboards")
@RestController
@RequestMapping("/api/v1/dashboards")
public class DashboardController {

    @Autowired
    private DashboardService dashboardService;

    @ApiOperation("List dashboards visible to the current user")
    @ApiImplicitParams({
            @ApiImplicitParam(name = "owner", value = "Filter by owner email", dataType = "string", paramType = "query"),
            @ApiImplicitParam(name = "sharedOnly", value = "Only return shared dashboards", dataType = "boolean", paramType = "query", defaultValue = "false")
    })
    @ApiResponses({
            @ApiResponse(code = 200, message = "Dashboards returned successfully"),
            @ApiResponse(code = 401, message = "Not authenticated")
    })
    @GetMapping
    public List<Dashboard> listDashboards(@RequestParam(required = false) String owner,
                                           @RequestParam(defaultValue = "false") boolean sharedOnly) {
        return dashboardService.find(owner, sharedOnly);
    }

    @ApiOperation("Create a new dashboard")
    @ApiResponses({
            @ApiResponse(code = 201, message = "Dashboard created"),
            @ApiResponse(code = 400, message = "Invalid dashboard payload")
    })
    @PostMapping
    public Dashboard createDashboard(@RequestBody Dashboard dashboard) {
        return dashboardService.save(dashboard);
    }

    @ApiOperation(value = "Delete a dashboard", notes = "Only the owner may delete a dashboard")
    @ApiResponses({
            @ApiResponse(code = 204, message = "Dashboard deleted"),
            @ApiResponse(code = 403, message = "Not the dashboard owner"),
            @ApiResponse(code = 404, message = "Dashboard not found")
    })
    @DeleteMapping("/{id}")
    public void deleteDashboard(@ApiParam("Dashboard id") @PathVariable Long id) {
        dashboardService.delete(id);
    }
}
