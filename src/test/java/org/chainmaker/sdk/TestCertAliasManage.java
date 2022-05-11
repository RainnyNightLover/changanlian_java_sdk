/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/
package org.chainmaker.sdk;

import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.util.encoders.Hex;
import org.chainmaker.pb.common.Request;
import org.chainmaker.pb.common.ResultOuterClass;
import org.chainmaker.sdk.utils.SdkUtils;
import org.junit.Assert;
import org.junit.Test;

public class TestCertAliasManage extends TestBase {

    private static final String certPem = "-----BEGIN CERTIFICATE-----\n"
            + "MIICdzCCAhygAwIBAgIDBF1PMAoGCCqGSM49BAMCMIGKMQswCQYDVQQGEwJDTjEQ\n"
            + "MA4GA1UECBMHQmVpamluZzEQMA4GA1UEBxMHQmVpamluZzEfMB0GA1UEChMWd3gt\n"
            + "b3JnMS5jaGFpbm1ha2VyLm9yZzESMBAGA1UECxMJcm9vdC1jZXJ0MSIwIAYDVQQD\n"
            + "ExljYS53eC1vcmcxLmNoYWlubWFrZXIub3JnMB4XDTIyMDEwNTA3MDg0MloXDTI3\n"
            + "MDEwNDA3MDg0MlowgY8xCzAJBgNVBAYTAkNOMRAwDgYDVQQIEwdCZWlqaW5nMRAw\n"
            + "DgYDVQQHEwdCZWlqaW5nMR8wHQYDVQQKExZ3eC1vcmcxLmNoYWlubWFrZXIub3Jn\n"
            + "MQ4wDAYDVQQLEwVhZG1pbjErMCkGA1UEAxMiYWRtaW4xLnNpZ24ud3gtb3JnMS5j\n"
            + "aGFpbm1ha2VyLm9yZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ/+wo+sLVrA\n"
            + "7wmpRnZlvv3wRnDdBkb0zZDohzJrNBE7WXzSzDVH4jPcLAv/nFoqGLrhB4fNDbMo\n"
            + "35Q7XYZ3kfKjajBoMA4GA1UdDwEB/wQEAwIGwDApBgNVHQ4EIgQgEMBTfnRMsaUO\n"
            + "m1b7uEKE2FwcqkHNPtZ1DAHGX64IiAYwKwYDVR0jBCQwIoAgWtS2YZiZccbsSxy0\n"
            + "gjVdGCD2PaBksn/TfzzWP9xx4UUwCgYIKoZIzj0EAwIDSQAwRgIhANIiDBs7SZem\n"
            + "GOsOeWIhENb576yKorRTi89Fa5RKqzgQAiEA/zqW4xzkoMq199/V1GwybDEqDJ3b\n"
            + "c0kQEac1sJyXsWY=\n"
            + "-----END CERTIFICATE-----\n";

    @Test
    public void testAddAlias() {
        ResultOuterClass.TxResponse responseInfo = null;
        try {
            responseInfo = chainClient.addAlias(rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(responseInfo);
    }

    @Test
    public void testQueryAlias() {
        ResultOuterClass.AliasInfos aliasInfos = null;
        try {
            String[] aliases = new String[]{"mycert4"};
            aliasInfos = chainClient.queryAlias(aliases, rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(aliasInfos);
    }

    @Test
    public void testDeleteAlias() {
        ResultOuterClass.TxResponse responseInfo = null;
        try {
            String[] aliases = new String[]{"mycert5"};
            Request.Payload payload = chainClient.createAliasDeletePayload(aliases);
            Request.EndorsementEntry[] endorsementEntries = SdkUtils
                    .getEndorsers(payload, new User[]{adminUser1, adminUser2, adminUser3});

            responseInfo = chainClient.deleteAlias(payload, endorsementEntries, rpcCallTimeout, syncResultTimeout);

        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(responseInfo);
    }

    @Test
    public void testUpdateAlias() {
        ResultOuterClass.TxResponse responseInfo = null;
        try {
            Request.Payload payload = chainClient.createUpdateAliasPayload("aliases", certPem);
            Request.EndorsementEntry[] endorsementEntries = SdkUtils
                    .getEndorsers(payload, new User[]{adminUser1, adminUser2, adminUser3});

            responseInfo = chainClient.updateAlias(payload, endorsementEntries, rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(responseInfo);
    }

}
