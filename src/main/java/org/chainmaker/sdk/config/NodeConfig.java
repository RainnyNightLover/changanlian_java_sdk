/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.config;

public class NodeConfig {

    public static final Integer maxConnCnt = 1024;

    private String nodeAddr;

    private int connCnt;

    private boolean enableTls;

    private String[] trustRootPaths;

    private byte[][] trustRootBytes;

    private String tlsHostName;

    public String getNode_addr() {
        return nodeAddr;
    }

    public void setNode_addr(String node_addr) {
        this.nodeAddr = node_addr;
    }

    public int getConn_cnt() {
        return connCnt;
    }

    public void setConn_cnt(int conn_cnt) {
        this.connCnt = conn_cnt;
    }

    public boolean isEnable_tls() {
        return enableTls;
    }

    public void setEnable_tls(boolean enable_tls) {
        this.enableTls = enable_tls;
    }

    public String[] getTrust_root_paths() {
        return trustRootPaths;
    }

    public void setTrust_root_paths(String[] trust_root_paths) {
        this.trustRootPaths = trust_root_paths;
    }

    public String getTls_host_name() {
        return tlsHostName;
    }

    public void setTls_host_name(String tls_host_name) {
        this.tlsHostName = tls_host_name;
    }

    public byte[][] getTrustRootBytes() {
        return trustRootBytes;
    }

    public void setTrustRootBytes(byte[][] trustRootBytes) {
        this.trustRootBytes = trustRootBytes;
    }

    public static Integer getMaxConnCnt() {
        return maxConnCnt;
    }

    public String getNodeAddr() {
        return nodeAddr;
    }

    public void setNodeAddr(String nodeAddr) {
        this.nodeAddr = nodeAddr;
    }

    public int getConnCnt() {
        return connCnt;
    }

    public void setConnCnt(int connCnt) {
        this.connCnt = connCnt;
    }

    public boolean isEnableTls() {
        return enableTls;
    }

    public void setEnableTls(boolean enableTls) {
        this.enableTls = enableTls;
    }

    public String[] getTrustRootPaths() {
        return trustRootPaths;
    }

    public void setTrustRootPaths(String[] trustRootPaths) {
        this.trustRootPaths = trustRootPaths;
    }

    public String getTlsHostName() {
        return tlsHostName;
    }

    public void setTlsHostName(String tlsHostName) {
        this.tlsHostName = tlsHostName;
    }
}
