package com.protect7.authanalyzer.util;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 对称采集：存储 A、B 两份 Original 响应及各 Run 的重放比较结果。
 */
public class SymmetricTrafficStore {

    private final Map<String, byte[]> responseA = new ConcurrentHashMap<>();
    private final Map<String, byte[]> responseB = new ConcurrentHashMap<>();
    private final Map<String, BypassConstants> replayStatusRun1 = new ConcurrentHashMap<>();
    private final Map<String, BypassConstants> replayStatusRun2 = new ConcurrentHashMap<>();

    public void putResponseA(String endpointKey, byte[] response) {
        if (endpointKey != null && response != null) {
            responseA.put(endpointKey, response);
        }
    }

    public void putResponseB(String endpointKey, byte[] response) {
        if (endpointKey != null && response != null) {
            responseB.put(endpointKey, response);
        }
    }

    public void putReplayStatusRun1(String endpointKey, BypassConstants status) {
        if (endpointKey != null && status != null) {
            replayStatusRun1.put(endpointKey, status);
        }
    }

    public void putReplayStatusRun2(String endpointKey, BypassConstants status) {
        if (endpointKey != null && status != null) {
            replayStatusRun2.put(endpointKey, status);
        }
    }

    public byte[] getResponseA(String endpointKey) {
        return endpointKey != null ? responseA.get(endpointKey) : null;
    }

    public byte[] getResponseB(String endpointKey) {
        return endpointKey != null ? responseB.get(endpointKey) : null;
    }

    public BypassConstants getReplayStatusRun1(String endpointKey) {
        return endpointKey != null ? replayStatusRun1.get(endpointKey) : null;
    }

    public BypassConstants getReplayStatusRun2(String endpointKey) {
        return endpointKey != null ? replayStatusRun2.get(endpointKey) : null;
    }

    public boolean hasResponseA(String endpointKey) {
        return endpointKey != null && responseA.containsKey(endpointKey);
    }

    public boolean hasResponseB(String endpointKey) {
        return endpointKey != null && responseB.containsKey(endpointKey);
    }

    public boolean hasBoth(String endpointKey) {
        return hasResponseA(endpointKey) && hasResponseB(endpointKey);
    }

    /** 所有待检查的 endpoint：responseA 与 responseB 的 key 并集 */
    public Set<String> getAllEndpointKeys() {
        Set<String> keys = new HashSet<>();
        keys.addAll(responseA.keySet());
        keys.addAll(responseB.keySet());
        return Collections.unmodifiableSet(keys);
    }

    public void clear() {
        responseA.clear();
        responseB.clear();
        replayStatusRun1.clear();
        replayStatusRun2.clear();
    }

    public int getResponseACount() {
        return responseA.size();
    }

    public int getResponseBCount() {
        return responseB.size();
    }

    public boolean isEmpty() {
        return responseA.isEmpty() && responseB.isEmpty();
    }
}
