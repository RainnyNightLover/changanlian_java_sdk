/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/
package org.chainmaker.sdk;

import org.chainmaker.pb.common.Request;
import org.chainmaker.pb.common.ResultOuterClass;
import org.chainmaker.pb.syscontract.AccountManager;
import org.chainmaker.sdk.utils.CryptoUtils;
import org.chainmaker.sdk.utils.SdkUtils;
import org.chainmaker.sdk.utils.UtilsException;
import org.junit.Assert;
import org.junit.Test;

import java.security.PublicKey;


public class TestGasManage extends TestBase {
    private static final String CONTRACT_FILE_PATH = "rust-fact-1.0.0.wasm";
    private static String addr = "";

    @Test
    public void testSetGasAdmin() throws UtilsException {
        addr = CryptoUtils.getZXAddressFromPKPEM(new String(chainClient.getClientUser().getPukBytes()));
        ResultOuterClass.TxResponse responseInfo = null;
        try {
            // 1. create payload
            Request.Payload payload = chainClient.createSetGasAdminPayload(addr);

            //2. create payloads with endorsement
            Request.EndorsementEntry[] endorsementEntries = SdkUtils
                    .getEndorsers(payload, new User[]{adminUser1, adminUser2, adminUser3});

            // 3. send request
            responseInfo = chainClient.sendGasManageRequest(payload, endorsementEntries, rpcCallTimeout, syncResultTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(responseInfo);
    }

    @Test
    public void testGetGasAdmin() {
        String addr = null;
        try {
            addr = chainClient.getGasAdmin(rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(addr);
    }

    @Test
    public void testRechargeGas() throws UtilsException{
        addr = CryptoUtils.getZXAddressFromPKPEM(new String(chainClient.getClientUser().getPukBytes()));
        Request.Payload payload;
        AccountManager.RechargeGas[] RechargeGasList = new AccountManager.RechargeGas[]{AccountManager.RechargeGas.newBuilder()
                .setAddress(addr)
                .setGasAmount(20).build()};

        ResultOuterClass.TxResponse responseInfo = null;
        try {
            // 1. create payload
            payload = chainClient.createRechargeGasPayload(RechargeGasList);

            // 2. send request
            responseInfo = chainClient.sendGasManageRequest(payload, null, rpcCallTimeout, syncResultTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(responseInfo);
    }

    @Test
    public void getGasBalance() throws UtilsException {
        addr = CryptoUtils.getZXAddressFromPKPEM(new String(chainClient.getClientUser().getPukBytes()));
        long balance = 0;
        try {
            balance = chainClient.getGasBalance(addr, rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        System.out.println(balance);
    }

    @Test
    public void testRefundGas() throws UtilsException {
        addr = CryptoUtils.getZXAddressFromPKPEM(new String(chainClient.getClientUser().getPukBytes()));
        Request.Payload payload;
        long balance = 0;
        ResultOuterClass.TxResponse responseInfo = null;
        try {
            // 1. create payload
            payload = chainClient.createRefundGasPayload(addr, 20);

            // 2. send request
            responseInfo = chainClient.sendGasManageRequest(payload, null, rpcCallTimeout, syncResultTimeout);

            // 3. get balance
            balance = chainClient.getGasBalance(addr, rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        System.out.println(balance);
        Assert.assertNotNull(responseInfo);
    }

    @Test
    public void getFrozenGasAccount() throws UtilsException {
        addr = CryptoUtils.getZXAddressFromPKPEM(new String(chainClient.getClientUser().getPukBytes()));
        ResultOuterClass.TxResponse responseInfo = null;
        try {
            // 1. create payload
            Request.Payload payload = chainClient.createFrozenGasAccountPayload(addr);
            // 2. send request
            responseInfo = chainClient.sendGasManageRequest(payload, null, rpcCallTimeout, syncResultTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(responseInfo);
    }

    @Test
    public void getUnFrozenGasAccount() throws UtilsException {
        addr = CryptoUtils.getZXAddressFromPKPEM(new String(chainClient.getClientUser().getPukBytes()));
        ResultOuterClass.TxResponse responseInfo = null;
        try {
            // 1. create payload
            Request.Payload payload = chainClient.createUnfrozenGasAccountPayload(addr);

            // 2. send request
            responseInfo = chainClient.sendGasManageRequest(payload, null, rpcCallTimeout, syncResultTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(responseInfo);
    }

    @Test
    public void getGasAccountStatus() {
        boolean status = false;
        try {
            String addr = chainClient.getGasAdmin(rpcCallTimeout);
            status = chainClient.getGasAccountStatus(addr, rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        System.out.println(status);
    }
}
