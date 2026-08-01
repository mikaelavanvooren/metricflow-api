package com.metricflow.api.service;

import com.metricflow.api.model.Metric;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class MetricsService {

    private final Map<Long, Metric> store = new ConcurrentHashMap<>();
    private final AtomicLong idGen = new AtomicLong(1);

    public List<Metric> findAll() {
        return List.copyOf(store.values());
    }

    public Metric findById(Long id) {
        return store.get(id);
    }

    public Metric save(Metric metric) {
        metric.setId(idGen.getAndIncrement());
        store.put(metric.getId(), metric);
        return metric;
    }
}
