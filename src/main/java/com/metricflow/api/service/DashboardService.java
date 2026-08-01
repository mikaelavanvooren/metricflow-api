package com.metricflow.api.service;

import com.metricflow.api.model.Dashboard;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

@Service
public class DashboardService {

    private final Map<Long, Dashboard> store = new ConcurrentHashMap<>();
    private final AtomicLong idGen = new AtomicLong(1);

    public List<Dashboard> find(String owner, boolean sharedOnly) {
        return store.values().stream()
                .filter(d -> owner == null || owner.equals(d.getOwner()))
                .filter(d -> !sharedOnly || d.isShared())
                .collect(Collectors.toList());
    }

    public Dashboard save(Dashboard dashboard) {
        dashboard.setId(idGen.getAndIncrement());
        store.put(dashboard.getId(), dashboard);
        return dashboard;
    }

    public void delete(Long id) {
        store.remove(id);
    }
}
