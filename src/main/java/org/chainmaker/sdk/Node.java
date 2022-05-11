/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk;

/*
 Node is the destination which a ChainClient connect to. It include the grpc address, hostname,
 negotiationType and client info(cert and key).
 */
public class Node {
    // node grpc address
    private String grpcUrl;
    // the organization's ca cert bytes
    private byte[][] tlsCertBytes;
    // the hostname in client certificate
    private String hostname;
    // TLS or PLAINTEXT
    private String negotiationType;
    // OPENSSL or JDK
    private String sslProvider;
    // node connect count
    private int connectCount;

    public String getGrpcUrl() {
        return grpcUrl;
    }

    public void setGrpcUrl(String grpcUrl) {
        this.grpcUrl = grpcUrl;
    }

    public byte[][] getTlsCertBytes() {
        return tlsCertBytes;
    }

    public void setTlsCertBytes(byte[][] tlsCertBytes) {
        this.tlsCertBytes = tlsCertBytes;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getNegotiationType() {
        return negotiationType;
    }

    public void setNegotiationType(String negotiationType) {
        this.negotiationType = negotiationType;
    }

    public String getSslProvider() {
        return sslProvider;
    }

    public void setSslProvider(String sslProvider) {
        this.sslProvider = sslProvider;
    }

    public int getConnectCount() {
        return connectCount;
    }

    public void setConnectCount(int connectCount) {
        this.connectCount = connectCount;
    }
}
