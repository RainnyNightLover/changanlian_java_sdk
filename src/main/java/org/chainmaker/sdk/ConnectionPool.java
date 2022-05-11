/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk;

import io.grpc.ConnectivityState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.List;

public class ConnectionPool {

    private static final Logger logger = LoggerFactory.getLogger(ConnectionPool.class);

    private  List<RpcServiceClient> rpcServiceClients;
    // user's private key used to tls
    private PrivateKey privateKey;
    // user's certificate
    private Certificate certificate;

    public List<RpcServiceClient> getRpcServiceClients() {
        return rpcServiceClients;
    }

    private int retryInterval = 500; //获取可用客户端连接对象重试时间间隔，单位：ms
    private int retryLimit = 10; // 获取可用客户端连接对象最大重试次数

    public void setRpcServiceClients(List<RpcServiceClient> rpcServiceClients) {
        this.rpcServiceClients = rpcServiceClients;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public int getRetryInterval() {
        return retryInterval;
    }

    public void setRetryInterval(int retryInterval) {
        this.retryInterval = retryInterval;
    }

    public int getRetryLimit() {
        return retryLimit;
    }

    public void setRetryLimit(int retryLimit) {
        this.retryLimit = retryLimit;
    }

    public RpcServiceClient getConnection() {
        for (int i = 0; i < retryLimit; i++) {
            for (RpcServiceClient rpcServiceClient : rpcServiceClients) {
                ConnectivityState connectivityState = rpcServiceClient.getManagedChannel().getState(true);
                if (connectivityState.equals(ConnectivityState.IDLE) || connectivityState.equals(ConnectivityState.READY)) {
                    return rpcServiceClient;
                }
            }
            try {
                Thread.sleep(retryInterval);
            } catch (InterruptedException e) {
                logger.error("Thread sleep error : ", e);
            }
        }
        //如果重试后还未获得，则提示重置连接数
        return null;
    }

    public void stop() {
        for (RpcServiceClient rpcServiceClient : rpcServiceClients) {
            rpcServiceClient.getManagedChannel().shutdown();
        }
    }

}
