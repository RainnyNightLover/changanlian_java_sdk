/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk;

import org.bouncycastle.util.encoders.Hex;
import org.chainmaker.pb.common.ChainmakerBlock;
import org.chainmaker.pb.common.ChainmakerTransaction;
import org.chainmaker.pb.common.Request;
import org.chainmaker.pb.common.ResultOuterClass;
import org.chainmaker.pb.config.ChainConfigOuterClass;
import org.chainmaker.pb.discovery.Discovery;
import org.chainmaker.pb.store.Store;
import org.chainmaker.pb.syscontract.SystemContractOuterClass;
import org.chainmaker.sdk.utils.SdkUtils;
import org.junit.Assert;
import org.junit.Test;

public class TestSystemContract extends TestBase {
    private static final String TX_ID = "5f5bc0630c8c153241668728bb7ea80407fabcb4d89d5b3585c460f76c621eca";
    private static final String BLOCK_HASH = "7cbe3bc13cea81a626cbe2f624a3aca5f57e0a6ec566247e2521032cf994d28b";

    @Test
    public void testGetTxByTxId() {
        ChainmakerTransaction.TransactionInfo response = null;
        try {
            response = chainClient.getTxByTxId(TX_ID, rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(response);
    }

    @Test
    public void testGetTxWithRWSetByTxId() {
        ChainmakerTransaction.TransactionInfoWithRWSet response = null;
        try {
            response = chainClient.getTxWithRWSetByTxId(TX_ID, rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(response);
    }


    @Test
    public void testGetBlockByHeight() {

        ChainmakerBlock.BlockInfo blockInfo = null;
        try {
            blockInfo = chainClient.getBlockByHeight(2, false, rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(blockInfo);
    }

    @Test
    public void testGetBlockByHash() {
        //BLOCK_HASH的计算方式为Hex.toHexString(blockInfo.getBlock().getHeader().getBlockHash().toByteArray())
        ChainmakerBlock.BlockInfo blockInfo = null;
        try {
            blockInfo = chainClient.getBlockByHash(BLOCK_HASH, false, rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(blockInfo);
    }

    @Test
    public void testGetBlockByTxId() {
        ChainmakerBlock.BlockInfo blockInfo = null;
        try {
            blockInfo = chainClient.getBlockByTxId(TX_ID, false, rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        System.out.println(Hex.toHexString(blockInfo.getBlock().getHeader().getBlockHash().toByteArray()));
        Assert.assertNotNull(blockInfo);
    }

    @Test
    public void testGetLastConfigBlock() {
        ChainmakerBlock.BlockInfo blockInfo = null;
        try {
            blockInfo = chainClient.getLastConfigBlock(false, rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(blockInfo);
    }

    @Test
    public void testGetNodeChainList() {
        Discovery.ChainList chainList = null;
        try {
            chainList = chainClient.getNodeChainList(rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(chainList);
    }

    @Test
    public void testGetChainInfo() {
        Discovery.ChainInfo chainInfo = null;
        try {
            chainInfo = chainClient.getChainInfo(rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(chainInfo);
    }

    @Test
    public void testEnableCertHash() {
        boolean success = false;
        try {
            success = chainClient.enableCertHash();
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertTrue(success);
    }

    @Test
    public void testGetBlockHeightByTxId() {
        long blockheight = 0;
        try {
            blockheight = chainClient.getBlockHeightByTxId(TX_ID, rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(blockheight);
    }

    @Test
    public void testGetBlockHeightByBlockHash() {
        long blockheight = 0;
        try {
            blockheight = chainClient.getBlockHeightByBlockHash(BLOCK_HASH, rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(blockheight);
    }

    @Test
    public void tetsGetFullBlockByHeight() {
        Store.BlockWithRWSet fullBlock = null;
        try {
            fullBlock = chainClient.getFullBlockByHeight(2, rpcCallTimeout);
        } catch (SdkException e) {
            Assert.fail(e.getMessage());
            e.printStackTrace();
        }
        Assert.assertNotNull(fullBlock);
    }

    @Test
    public void tetsGetLatestBlock() {
        ChainmakerBlock.BlockInfo blockInfo = null;
        try {
            blockInfo = chainClient.getLastBlock(false, rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(blockInfo);
    }

    @Test
    public void testGetCurrentBlockHeight() {
        long blockHeight = 0;
        try {
            blockHeight = chainClient.getCurrentBlockHeight(rpcCallTimeout);
        } catch (SdkException e) {
            Assert.fail(e.getMessage());
            e.printStackTrace();
        }
        Assert.assertNotNull(blockHeight);
    }

    @Test
    public void testGetBlockHeaderByHeight() {
        ChainmakerBlock.BlockHeader blockHeader = null;
        try {
            blockHeader = chainClient.getBlockHeaderByHeight(2, rpcCallTimeout);
        } catch (SdkException e) {
            Assert.fail(e.getMessage());
            e.printStackTrace();
        }
        Assert.assertNotNull(blockHeader);
    }

    @Test
    public void testNativeContractAccessGrant() {
        String[] toAddContractList = new String[]{SystemContractOuterClass.SystemContract.DPOS_ERC20.toString()};
        ResultOuterClass.TxResponse responseInfo = null;
        try {
            Request.Payload payload = chainClient.createNativeContractAccessGrantPayload(toAddContractList);
            Request.EndorsementEntry[] endorsementEntries = SdkUtils.getEndorsers(payload, new User[]{adminUser1, adminUser2, adminUser3});
            responseInfo = chainClient.sendContractManageRequest(payload, endorsementEntries, rpcCallTimeout, syncResultTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(responseInfo);
    }

    @Test
    public void testNativeContractAccessRevoke() {
        String[] revokeContractList = new String[]{SystemContractOuterClass.SystemContract.DPOS_ERC20.toString()};
        ResultOuterClass.TxResponse responseInfo = null;
        try {
            Request.Payload payload = chainClient.createNativeContractAccessRevokePayload(revokeContractList);
            Request.EndorsementEntry[] endorsementEntries = SdkUtils.getEndorsers(payload, new User[]{adminUser1, adminUser2, adminUser3});
            responseInfo = chainClient.sendContractManageRequest(payload, endorsementEntries, rpcCallTimeout, syncResultTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(responseInfo);
    }

    @Test
    public void testGetContractInfo() {
        String contractInfo = null;
        try {
            contractInfo = chainClient.getContractInfo("claim001", rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(contractInfo);
    }

    @Test
    public void testGetContractList() {
        String contractList = "";
        try {
            contractList = chainClient.getContractList(rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(contractList);
    }

    @Test
    public void testGetDisabledNativeContractList() {
        String disabledNativeContractList = "";
        try {
            disabledNativeContractList = chainClient.getDisabledNativeContractList(rpcCallTimeout);
        } catch (SdkException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertNotNull(disabledNativeContractList);
    }

}
