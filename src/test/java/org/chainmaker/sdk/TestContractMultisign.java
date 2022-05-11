/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk;

import org.chainmaker.pb.common.ContractOuterClass;
import org.chainmaker.pb.common.Request;
import org.chainmaker.pb.common.ResultOuterClass;
import org.chainmaker.pb.syscontract.ContractManage;
import org.chainmaker.pb.syscontract.MultiSign;
import org.chainmaker.pb.syscontract.SystemContractOuterClass;
import org.chainmaker.sdk.utils.FileUtils;
import org.chainmaker.sdk.utils.SdkUtils;
import org.chainmaker.sdk.utils.UtilsException;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class TestContractMultisign extends TestBase {

    private static final String CONTRACT_NAME = "test";
    private static final String CONTRACT_FILE_PATH = "rust-fact-1.0.0.wasm";

    public Map<String, byte[]> initContractParams() throws UtilsException {

        byte[] byteCode = FileUtils.getResourceFileBytes(CONTRACT_FILE_PATH);

        Map<String, byte[]> params = new HashMap<>();
        params.put(MultiSign.MultiReq.Parameter.SYS_CONTRACT_NAME.toString(),
                SystemContractOuterClass.SystemContract.CONTRACT_MANAGE.toString().getBytes());

        params.put(MultiSign.MultiReq.Parameter.SYS_METHOD.toString(),
                ContractManage.ContractManageFunction.INIT_CONTRACT.toString().getBytes());

        params.put(ContractManage.InitContract.Parameter.CONTRACT_NAME.toString(),
                CONTRACT_NAME.getBytes());

        params.put(ContractManage.InitContract.Parameter.CONTRACT_VERSION.toString(),
                "1.0".getBytes());

        params.put(ContractManage.InitContract.Parameter.CONTRACT_BYTECODE.toString(),
                byteCode);

        params.put(ContractManage.InitContract.Parameter.CONTRACT_RUNTIME_TYPE.toString(),
                ContractOuterClass.RuntimeType.WASMER.toString().getBytes());

        return params;
    }

    @Test
    public void testMultiSignReq() {
        ResultOuterClass.TxResponse response = null;
        try {
            Map<String, byte[]> params = initContractParams();
            Request.Payload payload = chainClient.createMultiSignReqPayload(params);
            response = chainClient.multiSignContractReq(payload, rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }

        Assert.assertNotNull(response);
    }

    @Test
    public void testMultiSignVote() {
        ResultOuterClass.TxResponse response = null;
        try {
            Map<String, byte[]> params = initContractParams();
            Request.Payload payload = chainClient.createMultiSignVotePayload(params);
            Request.EndorsementEntry[] endorsementEntries = SdkUtils.getEndorsers(payload, new User[]{adminUser1});
            response = chainClient.multiSignContractVote(payload, endorsementEntries[0], rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(response);
    }

    @Test
    public void testMultiSignQuery() {
        ResultOuterClass.TxResponse response = null;
        try {
            response = chainClient.multiSignContractQuery("", rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(response);
    }
}
