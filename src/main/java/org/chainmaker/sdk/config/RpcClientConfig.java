/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.config;

public class RpcClientConfig {
    private int maxReceiveMessageSize = 16;

    public int getMax_receive_message_size() {
        return maxReceiveMessageSize;
    }

    public void setMax_receive_message_size(int max_receive_message_size) {
        this.maxReceiveMessageSize = max_receive_message_size;
    }

    public int getMaxReceiveMessageSize() {
        return maxReceiveMessageSize;
    }

    public void setMaxReceiveMessageSize(int maxReceiveMessageSize) {
        this.maxReceiveMessageSize = maxReceiveMessageSize;
    }
}
