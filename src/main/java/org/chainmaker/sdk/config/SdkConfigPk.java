/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/
package org.chainmaker.sdk.config;

public class SdkConfigPk {

    private ChainClientConfig chainClient;

    public ChainClientConfig getChain_client() {
        return chainClient;
    }

    public void setChain_client(ChainClientConfig chain_client) {
        this.chainClient = chain_client;
    }

    public ChainClientConfig getChainClient() {
        return chainClient;
    }

    public void setChainClient(ChainClientConfig chainClient) {
        this.chainClient = chainClient;
    }
}
