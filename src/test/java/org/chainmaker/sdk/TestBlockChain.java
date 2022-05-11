/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/
package org.chainmaker.sdk;

import org.chainmaker.pb.config.LocalConfig.CheckNewBlockChainConfigResponse;
import org.junit.Assert;
import org.junit.Test;

public class TestBlockChain extends TestBase {

    @Test
    public void testCheckNewBlockChainConfig() {
        CheckNewBlockChainConfigResponse response = null;
        try {
            response = chainClient.checkNewBlockChainConfig(rpcCallTimeout);
        } catch (ChainClientException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(response);
    }

    @Test
    public void testGetChainMakerServerVersion() {
        String version = null;
        try {
            version = chainClient.getChainMakerServerVersion(rpcCallTimeout);
        } catch (ChainClientException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(version);
    }

    @Test
    public void testStop() {
        chainClient.stop();
    }
}
