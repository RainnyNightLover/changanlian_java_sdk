/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk;

import com.alibaba.fastjson.JSON;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import io.grpc.stub.StreamObserver;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.chainmaker.pb.accesscontrol.MemberOuterClass;
import org.chainmaker.pb.accesscontrol.MemberOuterClass.MemberType;
import org.chainmaker.pb.common.Request.TxType;
import org.chainmaker.pb.common.ResultOuterClass.AliasInfo;
import org.chainmaker.pb.common.ResultOuterClass.TxStatusCode;
import org.chainmaker.pb.config.ChainmakerServer.ChainMakerVersionRequest;
import org.chainmaker.pb.config.ChainmakerServer.ChainMakerVersionResponse;
import org.chainmaker.pb.config.LocalConfig.CheckNewBlockChainConfigRequest;
import org.chainmaker.pb.config.LocalConfig.CheckNewBlockChainConfigResponse;
import org.chainmaker.pb.store.Store;
import org.chainmaker.pb.accesscontrol.PolicyOuterClass;
import org.chainmaker.pb.common.ChainmakerBlock;
import org.chainmaker.pb.common.ResultOuterClass;
import org.chainmaker.pb.common.ContractOuterClass;
import org.chainmaker.pb.common.Request;
import org.chainmaker.pb.common.ChainmakerTransaction;
import org.chainmaker.pb.config.ChainConfigOuterClass;
import org.chainmaker.pb.discovery.Discovery;
import org.chainmaker.pb.syscontract.*;
import org.chainmaker.pb.syscontract.CertManage.CertManageFunction;
import org.chainmaker.pb.syscontract.ChainQuery.ChainQueryFunction;
import org.chainmaker.pb.syscontract.SystemContractOuterClass.SystemContract;
import org.chainmaker.sdk.config.ArchiveConfig;
import org.chainmaker.sdk.config.AuthType;
import org.chainmaker.sdk.crypto.ChainMakerCryptoSuiteException;
import org.chainmaker.sdk.utils.Utils;
import org.chainmaker.sdk.utils.UtilsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.CertificateEncodingException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static java.lang.String.format;

/*
 ChainClient is a client used to send transactions to chain nodes through rpc.
 */

public class ChainClient {
    // chainId is the identity of the chain
    private String chainId;
    // rpc connection Pool
    private ConnectionPool connectionPool;
    // archive config
    private ArchiveConfig archiveConfig;
    // the user used to sign transactions
    private User clientUser;

    public String getChainId() {
        return chainId;
    }

    public void setChainId(String chainId) {
        this.chainId = chainId;
    }

    public ConnectionPool getConnectionPool() {
        return connectionPool;
    }

    public void setConnectionPool(ConnectionPool connectionPool) {
        this.connectionPool = connectionPool;
    }

    public ArchiveConfig getArchiveConfig() {
        return archiveConfig;
    }

    public void setArchiveConfig(ArchiveConfig archiveConfig) {
        this.archiveConfig = archiveConfig;
    }

    public User getClientUser() {
        return clientUser;
    }

    public void setClientUser(User clientUser) {
        this.clientUser = clientUser;
    }

    private boolean isEnabledCertHash;

    private boolean isEnabledAlias;

    private static final String TX_ID = "txId";
    private static final String ORG_ID = "org_id";
    private static final String MEMBER_INFO = "member_info";
    private static final String NODE_ID = "node_id";
    private static final String ROLE = "role";
    private static final String NODE_IDS = "node_ids";
    private static final String BLOCK_HEIGHT = "blockHeight";
    private static final String BLOCK_HASH = "blockHash";
    private static final String WITH_RW_SET = "withRWSet";
    private static final long DEFAULT_RPC_TIMEOUT = 10000;
    private static final long DEFAULT_SYNC_RESULT_TIMEOUT = 10000;

    private static final String DRIVER_NAME = "com.mysql.cj.jdbc.Driver";
    private static final String MYSQL_DBNAME_PREFIX = "cm_archived_chain";
    private static final String MYSQL_TABLENAME_PREFIX = "t_block_info";
    private static final long ROWS_PREBLOCKINFO_TABLE = 100000;
    private static final long DEFAULT_SEQ = 0;
    private static final int SUCCESS = 0;

    private static final String KEYCERTHASHS = "cert_hashes";
    private static final String KEYCERTS = "certs";
    private static final String KEYCERTCRL = "cert_crl";

    private static final String KEY_PUBKEY = "pubkey";
    private static final String KEY_PUBKEY_ROLE = "role";
    private static final String KEY_PUBKEY_ORG_ID = "org_id";

    private static final String KEY_ALIAS = "alias";
    private static final String KEY_ALIASES = "aliases";

    private static final String KEY_CERT = "cert";

    private static final Logger logger = LoggerFactory.getLogger(ChainClient.class);

    private static final String KEY_GASPUBLIC = "public_key";
    private static final String KEY_GASADDRESSKEY       = "address_key";
    private static final String Key_GASBATCHRECHARGE = "batch_recharge";
    private static final String Key_GASBALANCEPUBLICKEY = "balance_public_key";
    private static final String Key_GASCHARGEPUBLICKEY  = "charge_public_key";
    private static final String Key_GASCHARGEGASAMOUNT  = "charge_gas_amount";
    private static final String Key_GASFROZENPUBLICKEY  = "frozen_public_key";

    public synchronized boolean enableAlias() throws ChainMakerCryptoSuiteException,
            ChainClientException {
        // 已经启用别名，直接返回
        if (isEnabledAlias) {
            return true;
        }

        if (!clientUser.getAuthType().equals(AuthType.PermissionedWithCert.getMsg())) {
            throw new ChainClientException("cert alias is not supported");
        }

        ResultOuterClass.TxResponse response = addAlias(DEFAULT_RPC_TIMEOUT);
        checkProposalRequestResp(response, false);

        // check cert hash
        for (int i = 0; i < 10; i++) {
            if (getCheckAlias()) {
                isEnabledAlias = true;
                return true;
            }
        }

        return  false;
    }

    // enable cert hash instead full cert to identify sender when sending transaction to chain node
    public synchronized boolean enableCertHash() throws ChainMakerCryptoSuiteException,
            ChainClientException {

        // 优先使用别名，如果开启了别名，直接忽略压缩证书
        if (isEnabledAlias) {
            return true;
        }

        if (!clientUser.getAuthType().equals(AuthType.PermissionedWithCert.getMsg())) {
            throw new ChainClientException("cert hash is not supported");
        }

        if (isEnabledCertHash) {
            return true;
        }
        // get certHash if needed
        if (clientUser.getCertHash() == null || clientUser.getCertHash().length == 0) {
            ChainConfigOuterClass.ChainConfig chainConfig = getChainConfig(DEFAULT_RPC_TIMEOUT);
            if (chainConfig == null) {
                throw new ChainClientException("get chain config from node failed, please try again later");
            }
            clientUser.setCertHash(getCertificateId(chainConfig.getCrypto().getHash()));
            if (clientUser.getCertHash() == null || clientUser.getCertHash().length == 0) {
                throw new ChainClientException("get certificate id failed");
            }
        }
        // check cert hash
        if (checkCertHashOnChain()) {
            isEnabledCertHash = true;
            return true;
        }
        ResultOuterClass.TxResponse responseInfo = addCert(DEFAULT_RPC_TIMEOUT);

        if (responseInfo == null || responseInfo.getCode() != ResultOuterClass.TxStatusCode.SUCCESS
            || responseInfo.getContractResult().getCode() != SUCCESS) {
            throw new ChainClientException("add cert failed");
        }
        // check cert hash
        for (int i = 0; i < 10; i++) {
            if (checkCertHashOnChain()) {
                isEnabledCertHash = true;
                return true;
            }
        }
        return false;
    }

    public synchronized void disableCertHash() {
        isEnabledCertHash = false;
    }

    private byte[] getCertHash() throws ChainMakerCryptoSuiteException,
            ChainClientException {
        ChainConfigOuterClass.ChainConfig chainConfig = getChainConfig(DEFAULT_RPC_TIMEOUT);
        return getCertificateId(chainConfig.getCrypto().getHash());
    }

    private byte[] getCertificateId(String hashType) throws ChainMakerCryptoSuiteException {
        if (clientUser.getCertBytes() == null || clientUser.getCertBytes().length == 0) {
            return new byte[0];
        }
        byte[] encodedCert;
        try {
            encodedCert = clientUser.getCertificate().getEncoded();
        } catch (CertificateEncodingException e) {
            logger.error("encoded cert err : ", e);
            throw new ChainMakerCryptoSuiteException("encoded cert err : " + e.getMessage());
        }
        if (encodedCert == null || encodedCert.length == 0) {
            return new byte[0];
        }

        Digest digest = getHashDigest(hashType);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.update(encodedCert, 0, encodedCert.length);
        digest.doFinal(hash, 0);

        return hash;
    }

    private Digest getHashDigest(String hashAlgorithm) {
        if ("SHA3".equals(hashAlgorithm)) {
            return new SHA3Digest();
        } else if ("SM3".equals(hashAlgorithm)) {
            return new SM3Digest();
        } else {
            // Default to SHA2
            return new SHA256Digest();
        }
    }

    private boolean checkCertHashOnChain() throws ChainClientException, ChainMakerCryptoSuiteException {
        byte[] certHash = clientUser.getCertHash();
        if (certHash == null || certHash.length == 0) {
            return false;
        }

        ResultOuterClass.CertInfos certInfos = queryCert(
                new String[]{ByteUtils.toHexString(certHash)}, DEFAULT_RPC_TIMEOUT);
        if (certInfos == null) {
            throw new ChainClientException("get cert infos failed");
        }
        if (certInfos.getCertInfosList().size() != 1 || certInfos.getCertInfos(0).getCert().isEmpty()) {
            return false;
        }
        return certInfos.getCertInfos(0).getHash().equals(ByteUtils.toHexString(certHash));
    }
    private boolean getCheckAlias() throws ChainClientException, ChainMakerCryptoSuiteException {
        ResultOuterClass.AliasInfos aliasInfos = queryAlias(new String[]{clientUser.getAlias()}, DEFAULT_RPC_TIMEOUT);
        if (aliasInfos == null) {
            throw new ChainClientException("get alias infos failed");
        }

        return aliasInfos.getAliasInfos(0).getAlias().equals(clientUser.getAlias());
    }

    // ### 1.1 创建合约payload
    // **参数说明**
    //   - contractName: 合约名
    //   - version: 版本号
    //   - byteCodes: 合约字节数组
    //   - runtimeType: 合约运行环境
    //   - params: 合约初始化参数
    public Request.Payload createContractCreatePayload(String contractName,
                                                       String version, byte[] byteCode,
                                                       ContractOuterClass.RuntimeType runtime,
                                                       Map<String, byte[]> params)
            throws ChainMakerCryptoSuiteException {

        return createContractManageWithByteCodePayload(contractName,
                ContractManage.ContractManageFunction.INIT_CONTRACT.toString(),
                version, byteCode, runtime, params);
    }

    // ### 1.2 创建升级合约payload
    // **参数说明**
    //   - contractName: 合约名
    //   - version: 版本号
    //   - byteCodes: 合约字节数组
    //   - runtimeType: 合约运行环境
    //   - params: 合约初始化参数
    public Request.Payload createContractUpgradePayload(String contractName, String version, byte[] byteCode,
                                                       ContractOuterClass.RuntimeType runtime,
                                                       Map<String, byte[]> params)
            throws ChainMakerCryptoSuiteException {

        return createContractManageWithByteCodePayload(contractName,
                ContractManage.ContractManageFunction.UPGRADE_CONTRACT.toString(),
                version, byteCode, runtime, params);
    }

    // ### 1.3 创建冻结合约payload
    // **参数说明**
    //   - contractName: 合约名
    public Request.Payload createContractFreezePayload(String contractName) throws ChainMakerCryptoSuiteException {
        return createContractManagePayload(contractName,
                                           ContractManage.ContractManageFunction.FREEZE_CONTRACT.toString());
    }

    // ### 1.4 创建解冻合约payload
    // **参数说明**
    //   - contractName: 合约名
    public Request.Payload createContractUnFreezePayload(String contractName) throws ChainMakerCryptoSuiteException {
        return createContractManagePayload(contractName,
                                           ContractManage.ContractManageFunction.UNFREEZE_CONTRACT.toString());
    }

    // ### 1.5 创建注销合约payload
    // **参数说明**
    //   - contractName: 合约名
    public Request.Payload createContractRevokePayload(String contractName) throws ChainMakerCryptoSuiteException {
        return createContractManagePayload(contractName,
                                           ContractManage.ContractManageFunction.REVOKE_CONTRACT.toString());
    }

    // ### 1.6 发送合约操作请求
    // **参数说明**
    //   - payload: 合约内容
    //   - endorsementEntries: 带签名的合约内容
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    //   - syncResultTimeout: 同步获取执行结果超时时间，小于等于0代表不等待执行结果，直接返回（返回信息里包含交易ID），单位：毫秒
    public ResultOuterClass.TxResponse sendContractManageRequest(Request.Payload payload,
                                                                 Request.EndorsementEntry[] endorsementEntries,
                                                                 long rpcCallTimeout, long syncResultTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {

        return sendContractRequest(payload, endorsementEntries, rpcCallTimeout, syncResultTimeout);
    }

    // ### 1.7 合约调用接口
    // **参数说明**
    //   - contractName: 合约名
    //   - method: 方法名
    //   - txId: 交易id
    //   - params: 执行参数
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    //   - syncResultTimeout: 同步获取执行结果超时时间，小于等于0代表不等待执行结果，直接返回（返回信息里包含交易ID），单位：毫秒
    public ResultOuterClass.TxResponse invokeContract(String contractName, String method, String txId,
                                                      Map<String, byte[]> params,
                                                      long rpcCallTimeout, long syncResultTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        Request.Payload payload = createPayload(txId, Request.TxType.INVOKE_CONTRACT,
                                                contractName, method, params, DEFAULT_SEQ);
        return sendContractRequest(payload, null, rpcCallTimeout, syncResultTimeout);
    }

    // ### 1.8 合约查询接口
    // **参数说明**
    //   - contractName: 合约名
    //   - method: 方法名
    //   - txId: 交易id
    //   - params: 执行参数
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public ResultOuterClass.TxResponse queryContract(String contractName, String method, String txId,
                                                     Map<String, byte[]> params, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {

        Request.Payload payload = createPayload(txId, Request.TxType.QUERY_CONTRACT,
                                                contractName, method, params, DEFAULT_SEQ);
        return sendContractRequest(payload, null, rpcCallTimeout, -1);
    }

    // ## 2 系统合约接口
    // ### 2.1 根据交易Id查询交易
    // **参数说明**
    //   - txId: 交易ID
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public ChainmakerTransaction.TransactionInfo getTxByTxId(String txId, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(TX_ID, txId.getBytes());

        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT,
                SystemContract.CHAIN_QUERY.toString(),
                ChainQuery.ChainQueryFunction.GET_TX_BY_TX_ID.toString(), params, DEFAULT_SEQ);
        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);
        ChainmakerTransaction.TransactionInfo transactionInfo;
        try {
            transactionInfo = ChainmakerTransaction.TransactionInfo.parseFrom(txResponse.getContractResult().getResult());
        } catch (InvalidProtocolBufferException e) {
            logger.error("transactionInfo parseFrom result : ", e);
            throw new ChainClientException("transactionInfo parseFrom result : " + e.getMessage());
        }
        return transactionInfo;
    }

    // ### 2.2 根据交易Id查询包含rwset的交易
    // **参数说明**
    //   - txId: 交易ID
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public ChainmakerTransaction.TransactionInfoWithRWSet getTxWithRWSetByTxId(String txId, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(TX_ID, txId.getBytes());
        params.put(WITH_RW_SET, String.valueOf(true).getBytes());

        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT,
                SystemContract.CHAIN_QUERY.toString(),
                ChainQuery.ChainQueryFunction.GET_TX_BY_TX_ID.toString(), params, DEFAULT_SEQ);
        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);

        checkProposalRequestResp(txResponse, true);

        ChainmakerTransaction.TransactionInfoWithRWSet transactionInfoWithRWSet;
        try {
            transactionInfoWithRWSet = ChainmakerTransaction.TransactionInfoWithRWSet.parseFrom(txResponse.getContractResult().getResult());
        } catch (InvalidProtocolBufferException e) {
            logger.error("transactionInfo parseFrom result : ", e);
            throw new ChainClientException("transactionInfo parseFrom result : " + e.getMessage());
        }
        return transactionInfoWithRWSet;
    }

    // ### 2.3 根据区块高度查询区块
    // **参数说明**
    //   - blockHeight: 区块高度
    //   - withRWSet: 是否返回读写集
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public ChainmakerBlock.BlockInfo getBlockByHeight(long blockHeight, boolean withRWSet, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {

        Map<String, byte[]> params = new HashMap<>();
        params.put(BLOCK_HEIGHT, String.valueOf(blockHeight).getBytes());
        params.put(WITH_RW_SET, String.valueOf(withRWSet).getBytes());

        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CHAIN_QUERY.toString(),
                ChainQuery.ChainQueryFunction.GET_BLOCK_BY_HEIGHT.toString(), params, DEFAULT_SEQ);
        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);
        checkProposalRequestResp(txResponse, true);
        ChainmakerBlock.BlockInfo blockInfo;
        try {
            blockInfo = ChainmakerBlock.BlockInfo.parseFrom(txResponse.getContractResult().getResult());
        } catch (InvalidProtocolBufferException e) {
            logger.error("blockInfo parseFrom result : ", e);
            throw new ChainClientException("blockInfo parseFrom result : " + e.getMessage());
        }

        return blockInfo;
    }

    // ### 2.4 根据区块哈希查询区块
    // **参数说明**
    //   - blockHash: 区块hash
    //   - withRWSet: 是否返回读写集
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public ChainmakerBlock.BlockInfo getBlockByHash(String blockHash, boolean withRWSet, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(BLOCK_HASH, blockHash.getBytes());
        params.put(WITH_RW_SET, String.valueOf(withRWSet).getBytes());

        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CHAIN_QUERY.toString(),
                ChainQuery.ChainQueryFunction.GET_BLOCK_BY_HASH.toString(), params, DEFAULT_SEQ);

        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);

        checkProposalRequestResp(txResponse, true);

        ChainmakerBlock.BlockInfo blockInfo;
        try {
            blockInfo = ChainmakerBlock.BlockInfo.parseFrom(txResponse.getContractResult().getResult());
        } catch (InvalidProtocolBufferException e) {
            logger.error("blockInfo parseFrom result : ", e);
            throw new ChainClientException("blockInfo parseFrom result : " + e.getMessage());
        }

        return blockInfo;
    }

    // ### 2.5 根据交易Id查询区块
    // **参数说明**
    //   - txId: 交易Id
    //   - withRWSet: 是否返回读写集
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public ChainmakerBlock.BlockInfo getBlockByTxId(String txId, boolean withRWSet, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(TX_ID, txId.getBytes());
        params.put(WITH_RW_SET, String.valueOf(withRWSet).getBytes());

        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CHAIN_QUERY.toString(),
                ChainQuery.ChainQueryFunction.GET_BLOCK_BY_TX_ID.toString(), params, DEFAULT_SEQ);

        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);
        checkProposalRequestResp(txResponse, true);
        ChainmakerBlock.BlockInfo blockInfo;
        try {
            blockInfo = ChainmakerBlock.BlockInfo.parseFrom(txResponse.getContractResult().getResult());
        } catch (InvalidProtocolBufferException e) {
            logger.error("blockInfo parseFrom result : ", e);
            throw new ChainClientException("blockInfo parseFrom result : " + e.getMessage());
        }

        return blockInfo;
    }

    // ### 2.6 查询上一个配置块
    // **参数说明**
    //   - withRWSet: 是否返回读写集
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public ChainmakerBlock.BlockInfo getLastConfigBlock(boolean withRWSet, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(WITH_RW_SET, Boolean.toString(withRWSet).getBytes());

        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CHAIN_QUERY.toString(),
                ChainQuery.ChainQueryFunction.GET_LAST_CONFIG_BLOCK.toString(), params, DEFAULT_SEQ);

        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);
        checkProposalRequestResp(txResponse, true);
        ChainmakerBlock.BlockInfo blockInfo;
        try {
            blockInfo = ChainmakerBlock.BlockInfo.parseFrom(txResponse.getContractResult().getResult());
        } catch (InvalidProtocolBufferException e) {
            logger.error("blockInfo parseFrom result : ", e);
            throw new ChainClientException("blockInfo parseFrom result : " + e.getMessage());
        }

        return blockInfo;
    }

    // ### 2.7 查询节点加入的链信息
    // **参数说明**
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Discovery.ChainList getNodeChainList(long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CHAIN_QUERY.toString(),
                ChainQueryFunction.GET_NODE_CHAIN_LIST.toString(), null, DEFAULT_SEQ);

        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);
        checkProposalRequestResp(txResponse, true);
        Discovery.ChainList chainList;
        try {
            chainList = Discovery.ChainList.parseFrom(txResponse.getContractResult().getResult());
        } catch (InvalidProtocolBufferException e) {
            logger.error("chainList parseFrom result : ", e);
            throw new ChainClientException("chainList parseFrom result : " + e.getMessage());
        }

        return chainList;
    }

    // ### 2.8 查询链信息
    // **参数说明**
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Discovery.ChainInfo getChainInfo(long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CHAIN_QUERY.toString(),
                ChainQueryFunction.GET_CHAIN_INFO.toString(), null, DEFAULT_SEQ);

        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);
        checkProposalRequestResp(txResponse, true);
        Discovery.ChainInfo chainInfo;
        try {
            chainInfo = Discovery.ChainInfo.parseFrom(txResponse.getContractResult().getResult());
        } catch (InvalidProtocolBufferException e) {
            logger.error("chainInfo parseFrom result : ", e);
            throw new ChainClientException("chainInfo parseFrom result : " + e.getMessage());
        }

        return chainInfo;
    }

    // ### 2.9 根据txId查询区块高度
    // **参数说明**
    //   - txId: 交易id
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public long getBlockHeightByTxId(String txId, long rpcCallTimeout) throws ChainMakerCryptoSuiteException, ChainClientException {
        return getBlockHeight(txId, null, rpcCallTimeout);
    }

    // ### 2.10 根据blockHash查询区块高度
    // **参数说明**
    //   - blockHash: 区块哈希
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public long getBlockHeightByBlockHash(String blockHash, long timeout) throws ChainMakerCryptoSuiteException, ChainClientException {
        return getBlockHeight("", blockHash, timeout);
    }

    // ### 2.11 根据区块高度查询完整区块
    // **参数说明**
    //   - blockHeight: 区块高度
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Store.BlockWithRWSet getFullBlockByHeight(long blockHeight, long rpcCallTimeout)
            throws ChainClientException, ChainMakerCryptoSuiteException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(BLOCK_HEIGHT, String.valueOf(blockHeight).getBytes());

        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CHAIN_QUERY.toString(),
                ChainQuery.ChainQueryFunction.GET_FULL_BLOCK_BY_HEIGHT.toString(), params, DEFAULT_SEQ);

        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);

        checkProposalRequestResp(txResponse, true);

        Store.BlockWithRWSet blockWithRWSet;
        try {
            blockWithRWSet = Store.BlockWithRWSet.parseFrom(txResponse.getContractResult().getResult());
        } catch (InvalidProtocolBufferException e) {
            logger.error("blockWithRWSet parseFrom result : ", e);
            throw new ChainClientException("blockWithRWSet parseFrom result : " + e.getMessage());
        }

        return blockWithRWSet;
    }

    // ### 2.12 查询最新区块信息
    // **参数说明**
    //   - withRWSet: 是否返回读写集
    public ChainmakerBlock.BlockInfo getLastBlock(boolean withRWSet, long rpcCallTimeout)
            throws ChainClientException, ChainMakerCryptoSuiteException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(WITH_RW_SET, Boolean.toString(withRWSet).getBytes());

        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CHAIN_QUERY.toString(),
                ChainQuery.ChainQueryFunction.GET_LAST_BLOCK.toString(), params, DEFAULT_SEQ);

        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);

        checkProposalRequestResp(txResponse, true);

        ChainmakerBlock.BlockInfo blockInfo;
        try {
            blockInfo = ChainmakerBlock.BlockInfo.parseFrom(txResponse.getContractResult().getResult());
        } catch (InvalidProtocolBufferException e) {
            logger.error("blockInfo parseFrom result : ", e);
            throw new ChainClientException("blockInfo parseFrom result : " + e.getMessage());
        }

        return blockInfo;
    }

    // ### 2.13 查询最新区块高度
    public long getCurrentBlockHeight(long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        ChainmakerBlock.BlockInfo blockInfo = getLastBlock(false, rpcCallTimeout);
        return blockInfo.getBlock().getHeader().getBlockHeight();
    }

    // ### 2.14 根据区块高度查询区块头
    // **参数说明**
    //   - 区块高度: blockHeight
    public ChainmakerBlock.BlockHeader getBlockHeaderByHeight(long blockHeight, long rpcCallTimeout)
            throws ChainClientException, ChainMakerCryptoSuiteException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(BLOCK_HEIGHT, Long.toString(blockHeight).getBytes());

        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CHAIN_QUERY.toString(),
                ChainQuery.ChainQueryFunction.GET_BLOCK_HEADER_BY_HEIGHT.toString(), params, DEFAULT_SEQ);

        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);

        checkProposalRequestResp(txResponse, true);

        ChainmakerBlock.BlockHeader blockHeader;
        try {
            blockHeader = ChainmakerBlock.BlockHeader.parseFrom(txResponse.getContractResult().getResult());
        } catch (InvalidProtocolBufferException e) {
            logger.error("blockHeader parseFrom result : ", e);
            throw new ChainClientException("blockHeader parseFrom result : " + e.getMessage());
        }
        return blockHeader;
    }

    // ### 2.15 系统合约调用
    // **参数说明**
    //   - contractName: 合约名
    //   - method: 方法名
    //   - txId: 交易id
    //   - params: 执行参数
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    //   - syncResultTimeout: 同步获取执行结果超时时间，小于等于0代表不等待执行结果，直接返回（返回信息里包含交易ID），单位：毫秒
    public ResultOuterClass.TxResponse invokeSystemContract(String contractName, String method, String txId,  Map<String, byte[]> params,
                                                      long rpcCallTimeout, long syncResultTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        Request.Payload payload = createPayload(txId, Request.TxType.INVOKE_CONTRACT, contractName, method, params, DEFAULT_SEQ);
        return sendContractRequest(payload, null, rpcCallTimeout, syncResultTimeout);
    }

    // ### 2.16 合约查询接口
    // **参数说明**
    //   - contractName: 合约名
    //   - method: 方法名
    //   - txId: 交易id
    //   - params: 执行参数
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public ResultOuterClass.TxResponse querySystemContract(String contractName, String method, String txId,
                                                     Map<String, byte[]> params, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {

        Request.Payload payload = createPayload(txId, Request.TxType.QUERY_CONTRACT, contractName, method, params, DEFAULT_SEQ);
        return sendContractRequest(payload, null, rpcCallTimeout, -1);
    }

    // ### 2.17 根据交易Id获取Merkle路径
    // **参数说明**
    //   - txId: 交易ID
    public byte[] getMerklePathByTxId(String txId, long rpcCallTimeout) throws ChainMakerCryptoSuiteException, ChainClientException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(TX_ID, txId.getBytes());

        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CHAIN_QUERY.toString(),
                ChainQuery.ChainQueryFunction.GET_MERKLE_PATH_BY_TX_ID.toString(), params, DEFAULT_SEQ);

        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);

        return txResponse.getContractResult().getResult().toByteArray();
    }

    // ### 2.18 开放系统合约
    // **参数说明**
    //   - grantContractList: 需要开放的系统合约字符串数组
    public Request.Payload createNativeContractAccessGrantPayload(String[] grantContractList) throws ChainMakerCryptoSuiteException {
        return createNativeContractAccessPayload(ContractManage.ContractManageFunction.GRANT_CONTRACT_ACCESS.toString(), grantContractList);
    }

    // ### 2.19 弃用系统合约
    // **参数说明**
    //   - revokeContractList: 需要弃用的系统合约字符串数组
    public Request.Payload createNativeContractAccessRevokePayload(String[] revokeContractList) throws ChainMakerCryptoSuiteException {
        return createNativeContractAccessPayload(ContractManage.ContractManageFunction.REVOKE_CONTRACT_ACCESS.toString(), revokeContractList);
    }

    // ### 2.20 查询弃用的系统合约名单
    public Request.Payload createGetDisabledNativeContractListPayload() throws ChainMakerCryptoSuiteException {
        return createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CONTRACT_MANAGE.toString(),
                ContractManage.ContractQueryFunction.GET_DISABLED_CONTRACT_LIST.toString(), null, DEFAULT_SEQ);
    }

    // ### 2.21 查询指定合约的信息，包括系统合约和用户合约
    // **参数说明**
    //   - contractName: 指定查询的合约名字，包括系统合约和用户合约
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public String getContractInfo(String contractName, long rpcCallTimeout) throws ChainMakerCryptoSuiteException, ChainClientException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(ContractManage.GetContractInfo.Parameter.CONTRACT_NAME.toString(), contractName.getBytes());
        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CONTRACT_MANAGE.toString(),
                ContractManage.ContractQueryFunction.GET_CONTRACT_INFO.toString(), params, DEFAULT_SEQ);
        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);
        return txResponse.getContractResult().getResult().toStringUtf8();
    }


    // ### 2.22 查询所有的合约名单，包括系统合约和用户合约
    public String getContractList(long rpcCallTimeout) throws ChainMakerCryptoSuiteException, ChainClientException {
        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CONTRACT_MANAGE.toString(),
                ContractManage.ContractQueryFunction.GET_CONTRACT_LIST.toString(), null, DEFAULT_SEQ);
        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);
        return txResponse.getContractResult().getResult().toStringUtf8();
    }

    // ### 2.23 查询已禁用的系统合约名单
    public String getDisabledNativeContractList(long rpcCallTimeout) throws ChainMakerCryptoSuiteException, ChainClientException {
        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CONTRACT_MANAGE.toString(),
                ContractManage.ContractQueryFunction.GET_DISABLED_CONTRACT_LIST.toString(), null, DEFAULT_SEQ);
        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);
        return txResponse.getContractResult().getResult().toStringUtf8();
    }


    // ## 3 链配置接口
    // ### 3.1 查询最新链配置
    // **参数说明**
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public ChainConfigOuterClass.ChainConfig getChainConfig(long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.GET_CHAIN_CONFIG.toString(), null, DEFAULT_SEQ);

        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);

        checkProposalRequestResp(txResponse, true);

        ChainConfigOuterClass.ChainConfig chainConfig;
        try {
            chainConfig = ChainConfigOuterClass.ChainConfig.parseFrom(txResponse.getContractResult().getResult());
        } catch (InvalidProtocolBufferException e) {
            logger.error("chainConfig parseFrom result : ", e);
            throw new ChainClientException("chainConfig parseFrom result : " + e.getMessage());
        }
        return chainConfig;
    }

    // ### 3.2 根据指定区块高度查询最近链配置
    // **参数说明**
    //   - blockHeight: 区块高度
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public ChainConfigOuterClass.ChainConfig getChainConfigByBlockHeight(long blockHeight, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        Map<String, byte[]> params = new HashMap<>();
        params.put("block_height", String.valueOf(blockHeight).getBytes());

        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.GET_CHAIN_CONFIG_AT.toString(), params, DEFAULT_SEQ);

        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);

        checkProposalRequestResp(txResponse, true);

        ChainConfigOuterClass.ChainConfig chainConfig;
        try {
            chainConfig = ChainConfigOuterClass.ChainConfig.parseFrom(txResponse.getContractResult().getResult());
        } catch (InvalidProtocolBufferException e) {
            logger.error("ChainConfig parseFrom result : ", e);
            throw new ChainClientException("ChainConfig parseFrom result : " + e.getMessage());
        }

        return chainConfig;
    }

    // ### 3.3 查询最新链配置序号Sequence
    // **参数说明**
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public long getChainConfigSequence(long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        ChainConfigOuterClass.ChainConfig chainConfig = getChainConfig(rpcCallTimeout);
        return chainConfig.getSequence();
    }

    // ### 3.4 更新Core模块待签名payload生成
    // **参数说明**
    //   - txSchedulerTimeout: 交易调度器从交易池拿到交易后, 进行调度的时间，其值范围为[0, 60]，若无需修改，请置为-1
    //   - txSchedulerValidateTimeout: 交易调度器从区块中拿到交易后, 进行验证的超时时间，其值范围为[0, 60]，若无需修改，请置为-1
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Request.Payload createPayloadOfChainConfigCoreUpdate(int txSchedulerTimeout, int txSchedulerValidateTimeout, long rpcCallTimeout)
            throws ChainClientException, ChainMakerCryptoSuiteException {
        if (txSchedulerTimeout > 60 || txSchedulerValidateTimeout > 60) {
            throw new ChainClientException("invalid txSchedulerTimeout or txSchedulerValidateTimeout");
        }
        long sequence = getChainConfigSequence(rpcCallTimeout);
        Map<String, byte[]> params = new HashMap<>();
        if (txSchedulerTimeout > 0) {
            params.put("tx_scheduler_timeout", String.valueOf(txSchedulerTimeout).getBytes());
        }
        if (txSchedulerValidateTimeout > 0) {
            params.put("tx_scheduler_validate_timeout", String.valueOf(txSchedulerTimeout).getBytes());
        }

        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.CORE_UPDATE.toString(), params, sequence + 1);
    }

    // ### 3.5 更新Core模块待签名payload生成
    // **参数说明**
    //   - txTimestampVerify: 是否需要开启交易时间戳校验
    //   - (以下参数，若无需修改，请置为-1)
    //   - txTimeout: 交易时间戳的过期时间(秒)，其值范围为[600, +∞)
    //   - blockTxCapacity: 区块中最大交易数，其值范围为(0, +∞]
    //   - blockSize: 区块最大限制，单位MB，其值范围为(0, +∞]
    //   - blockInterval: 出块间隔，单位:ms，其值范围为[10, +∞]
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Request.Payload createPayloadOfChainConfigBlockUpdate(boolean txTimestampVerify, int txTimeout, int blockTxCapacity,
                                                        int blockSize, int blockInterval, int txParamterSize, long rpcCallTimeout)
            throws ChainClientException, ChainMakerCryptoSuiteException {
        if (txTimeout < 600 || blockTxCapacity < 1 || blockSize < 1 || blockInterval < 10) {
            throw new ChainClientException("invalid parameters");
        }
        long sequence = getChainConfigSequence(rpcCallTimeout);
        Map<String, byte[]> params = new HashMap<>();
        params.put("tx_timestamp_verify", String.valueOf(txTimestampVerify).getBytes());

        params.put("tx_timeout", String.valueOf(txTimeout).getBytes());
        params.put("block_tx_capacity", String.valueOf(blockTxCapacity).getBytes());
        params.put("block_size", String.valueOf(blockSize).getBytes());
        params.put("block_interval", String.valueOf(blockInterval).getBytes());
        params.put("tx_parameter_size", String.valueOf(txParamterSize).getBytes());

        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.BLOCK_UPDATE.toString(), params, sequence + 1);
    }

    // ### 3.6 添加信任组织根证书待签名payload生成
    // **参数说明**
    //   - trustRootOrgId: 组织Id
    //   - trustRootCrt: 根证书
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Request.Payload createPayloadOfChainConfigTrustRootAdd(String trustRootOrgId, String[] trustRootCrt, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        long sequence = getChainConfigSequence(rpcCallTimeout);
        Map<String, byte[]> params = new HashMap<>();
        params.put(ORG_ID, trustRootOrgId.getBytes());
        if (trustRootCrt.length > 0) {
            params.put("root", Utils.joinList(trustRootCrt).getBytes());
        }

        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.TRUST_ROOT_ADD.toString(), params, sequence + 1);
    }

    // ### 3.7 更新信任组织根证书待签名payload生成
    // **参数说明**
    //   - trustRootOrgId: 组织Id
    //   - trustRootCrt: 根证书
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Request.Payload createPayloadOfChainConfigTrustRootUpdate(String trustRootOrgId, String[] trustRootCrt, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        long sequence = getChainConfigSequence(rpcCallTimeout);
        Map<String, byte[]> params = new HashMap<>();
        params.put(ORG_ID, trustRootOrgId.getBytes());
        if (trustRootCrt.length > 0) {
            params.put("root", Utils.joinList(trustRootCrt).getBytes());
        }
        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.TRUST_ROOT_UPDATE.toString(), params, sequence + 1);
    }

    // ### 3.8 删除信任组织根证书待签名payload生成
    // **参数说明**
    //   - trustRootOrgId: 组织Id
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Request.Payload createPayloadOfChainConfigTrustRootDelete(String trustRootOrgId, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        long sequence = getChainConfigSequence(rpcCallTimeout);
        Map<String, byte[]> params = new HashMap<>();
        params.put(ORG_ID, trustRootOrgId.getBytes());

        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.TRUST_ROOT_DELETE.toString(), params, sequence + 1);
    }

    // ### 3.9 添加权限配置待签名payload生成
    // **参数说明**
    //   - permissionResourceName: 权限名
    //   - principle: 权限规则
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Request.Payload createPayloadOfChainConfigPermissionAdd(String permissionResourceName,
                                                          PolicyOuterClass.Policy principal, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        long sequence = getChainConfigSequence(rpcCallTimeout);
        Map<String, byte[]> params = new HashMap<>();
        params.put(permissionResourceName, principal.toByteArray());

        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.PERMISSION_ADD.toString(), params, sequence + 1);
    }

    // ### 3.10 更新权限配置待签名payload生成
    // **参数说明**
    //   - permissionResourceName: 权限名
    //   - principle: 权限规则
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Request.Payload createPayloadOfChainConfigPermissionUpdate(String permissionResourceName,
                                                             PolicyOuterClass.Policy principal, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {

        long sequence = getChainConfigSequence(rpcCallTimeout);
        Map<String, byte[]> params = new HashMap<>();
        params.put(permissionResourceName, principal.toByteArray());

        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.PERMISSION_UPDATE.toString(), params, sequence + 1);

    }

    // ### 3.11 删除权限配置待签名payload生成
    // **参数说明**
    //   - permissionResourceName: 权限名
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Request.Payload createPayloadOfChainConfigPermissionDelete(String permissionResourceName, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        long sequence = getChainConfigSequence(rpcCallTimeout);
        Map<String, byte[]> params = new HashMap<>();
        params.put(permissionResourceName, "".getBytes());

        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.PERMISSION_DELETE.toString(), params, sequence + 1);
    }

    // ### 3.12 添加共识节点地址待签名payload生成
    // **参数说明**
    //   - nodeOrgId: 节点组织Id
    //   - nodeAddresses: 节点地址
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Request.Payload createPayloadOfChainConfigConsensusNodeAddrAdd(String nodeOrgId, String[] nodeAddresses, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        long sequence = getChainConfigSequence(rpcCallTimeout);
        Map<String, byte[]> params = new HashMap<>();
        params.put(ORG_ID, nodeOrgId.getBytes());
        if (nodeAddresses.length > 0) {
            params.put(NODE_IDS, Utils.joinList(nodeAddresses).getBytes());
        }

        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.NODE_ID_ADD.toString(), params, sequence + 1);
    }

    // ### 3.13 更新共识节点地址待签名payload生成
    // **参数说明**
    //   - nodeOrgId: 节点组织Id
    //   - nodeOldAddress: 节点原地址
    //   - nodeNewAddress: 节点新地址
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Request.Payload createPayloadOfChainConfigConsensusNodeAddrUpdate(String nodeOrgId, String nodeOldAddress,
                                                                    String nodeNewAddress, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        long sequence = getChainConfigSequence(rpcCallTimeout);
        Map<String, byte[]> params = new HashMap<>();
        params.put(ORG_ID, nodeOrgId.getBytes());
        params.put("node_id", nodeOldAddress.getBytes());
        params.put("new_node_id", nodeNewAddress.getBytes());
        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.NODE_ID_UPDATE.toString(), params, sequence + 1);
    }

    // ### 3.14 删除共识节点地址待签名payload生成
    // **参数说明**
    //   - nodeOrgId: 节点组织Id
    //   - nodeAddress: 节点地址
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Request.Payload createPayloadOfChainConfigConsensusNodeAddrDelete(String nodeOrgId, String nodeAddress, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        long sequence = getChainConfigSequence(rpcCallTimeout);
        Map<String, byte[]> params = new HashMap<>();
        params.put(ORG_ID, nodeOrgId.getBytes());
        params.put("node_id", nodeAddress.getBytes());
        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.NODE_ID_DELETE.toString(), params, sequence + 1);
    }

    // ### 3.15 添加共识节点待签名payload生成
    // **参数说明**
    //   - nodeOrgId: 节点组织Id
    //   - nodeAddresses: 节点地址
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Request.Payload createPayloadOfChainConfigConsensusNodeOrgAdd(String nodeOrgId, String[] nodeAddresses, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        long sequence = getChainConfigSequence(rpcCallTimeout);
        Map<String, byte[]> params = new HashMap<>();
        params.put(ORG_ID, nodeOrgId.getBytes());
        if (nodeAddresses.length > 0) {
            params.put(NODE_IDS, Utils.joinList(nodeAddresses).getBytes());
        }
        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.NODE_ORG_ADD.toString(), params, sequence + 1);
    }

    // ### 3.16 更新共识节点待签名payload生成
    // **参数说明**
    //   - nodeOrgId: 节点组织Id
    //   - nodeAddresses: 节点地址
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Request.Payload createPayloadOfChainConfigConsensusNodeOrgUpdate(String nodeOrgId, String[] nodeAddresses, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        long sequence = getChainConfigSequence(rpcCallTimeout);
        Map<String, byte[]> params = new HashMap<>();
        params.put(ORG_ID, nodeOrgId.getBytes());
        if (nodeAddresses.length > 0) {
            params.put(NODE_IDS, Utils.joinList(nodeAddresses).getBytes());
        }
        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.NODE_ORG_UPDATE.toString(), params, sequence + 1);
    }

    // ### 3.17 删除共识节点待签名payload生成
    // **参数说明**
    //   - nodeOrgId: 节点组织Id
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Request.Payload createPayloadOfChainConfigConsensusNodeOrgDelete(String nodeOrgId, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {

        long sequence = getChainConfigSequence(rpcCallTimeout);
        Map<String, byte[]> params = new HashMap<>();
        params.put(ORG_ID, nodeOrgId.getBytes());
        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.NODE_ORG_DELETE.toString(), params, sequence + 1);
    }

    // ### 3.18 添加共识扩展字段待签名payload生成
    // **参数说明**
    //   - params: Map<String, byte[]>
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    public Request.Payload createPayloadOfChainConfigConsensusExtAdd(Map<String, byte[]> params, long rpcCallTimeout)
            throws  ChainMakerCryptoSuiteException, ChainClientException {

        long sequence = getChainConfigSequence(rpcCallTimeout);
        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.CONSENSUS_EXT_ADD.toString(), params, sequence + 1);
    }

    // ### 3.19 添加共识扩展字段待签名payload生成
    // **参数说明**
    //   - params: Map<String, byte[]>
    public Request.Payload createPayloadOfChainConfigConsensusExtUpdate(Map<String, byte[]> params, long rpcCallTimeout)
            throws  ChainMakerCryptoSuiteException, ChainClientException {
        long sequence = getChainConfigSequence(rpcCallTimeout);
        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.CONSENSUS_EXT_UPDATE.toString(), params, sequence + 1);
    }

    // ### 3.20 添加共识扩展字段待签名payload生成
    // **参数说明**
    //   - keys: 待删除字段
    public Request.Payload createPayloadOfChainConfigConsensusExtDelete(String[] keys, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {

        Map<String, byte[]> params = new HashMap<>();
        if (keys.length > 0) {
            for (String key : keys) {
                params.put(key, "".getBytes());
            }
        }
        long sequence = getChainConfigSequence(rpcCallTimeout);
        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.CONSENSUS_EXT_DELETE.toString(), params, sequence + 1);
    }

    // ### 3.21 添加信任成员证书待签名payload生成
    // **参数说明**
    //   - trustMemberOrgId: 组织Id
    //   - trustMemberNodeId: 节点Id
    //   - trustMemberRole: 成员角色
    //   - trustMemberInfo: 成员信息内容
    public Request.Payload createChainConfigTrustMemberAddPayload(String trustMemberOrgId, String trustMemberNodeId, String trustMemberRole,
                                                                  String trustMemberInfo, long rpcCallTimeout)
            throws ChainClientException, ChainMakerCryptoSuiteException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(ORG_ID, trustMemberOrgId.getBytes());
        params.put(MEMBER_INFO, trustMemberInfo.getBytes());
        params.put(NODE_ID, trustMemberNodeId.getBytes());
        params.put(ROLE, trustMemberRole.getBytes());

        long sequence = getChainConfigSequence(rpcCallTimeout);

        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.TRUST_MEMBER_ADD.toString(), params, sequence + 1);
    }

    // ### 3.22 删除信任成员证书待签名payload生成
    // **参数说明**
    //   - trustMemberInfo: 成员信息内容
    public Request.Payload createChainConfigTrustMemberAddPayload(String trustMemberInfo, long rpcCallTimeout)
            throws ChainClientException, ChainMakerCryptoSuiteException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(MEMBER_INFO, trustMemberInfo.getBytes());

        long sequence = getChainConfigSequence(rpcCallTimeout);

        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.TRUST_MEMBER_DELETE.toString(), params, sequence + 1);
    }

    // ### 3.23 发送链配置更新请求
    public ResultOuterClass.TxResponse updateChainConfig(Request.Payload payload, Request.EndorsementEntry[] endorsementEntries,
                                          long rpcCallTimeout, long syncResultTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        return sendContractRequest(payload, endorsementEntries, rpcCallTimeout, syncResultTimeout);
    }

    // ## 4 证书管理接口
    // ### 4.1 用户证书添加
    // **参数说明**
    //   - 在pb.TxResponse.ContractResult.Result字段中返回成功添加的certHash
    public ResultOuterClass.TxResponse addCert(long rpcCallTimeout) throws ChainMakerCryptoSuiteException,
            ChainClientException {
        byte[] certHash = getCertHash();
        Request.Payload payload = createCertManagePayload(CertManage.CertManageFunction.CERT_ADD.toString(), null);
        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);

        checkProposalRequestResp(txResponse, false);

        ResultOuterClass.TxResponse.Builder txResponseBuilder = txResponse.toBuilder();
        txResponseBuilder.setContractResult(ResultOuterClass.ContractResult.newBuilder().setResult(ByteString.copyFrom(certHash)));

        return txResponseBuilder.build();
    }

    // ### 4.2 用户证书删除
    // **参数说明**
    //   - payload: 合约内容
    //   - endorsementEntries: 带签名的合约内容
    public ResultOuterClass.TxResponse deleteCert(Request.Payload payload, Request.EndorsementEntry[] endorsementEntries,
                                                  long rpcCallTimeout, long syncResultTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {

        return sendContractRequest(payload, endorsementEntries, rpcCallTimeout, syncResultTimeout);
    }

    // ### 4.3 用户证书查询
    // **参数说明**
    //   - certHashes: 证书Hash列表
    // 返回值说明：
    //   - *pb.CertInfos: 包含证书Hash和证书内容的列表
    public ResultOuterClass.CertInfos queryCert(String[] certHashes, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        Map<String, byte[]> params = new HashMap<>();
        if (certHashes.length > 0) {
            params.put(KEYCERTHASHS, Utils.joinList(certHashes).getBytes());
        }
        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT,
                SystemContract.CERT_MANAGE.toString(), CertManage.CertManageFunction.CERTS_QUERY.toString(), params, DEFAULT_SEQ);
        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);

        ResultOuterClass.CertInfos certInfos;
        try {
            certInfos = ResultOuterClass.CertInfos.parseFrom(txResponse.getContractResult().getResult());
        } catch (InvalidProtocolBufferException e) {
            logger.error("certInfos parseFrom result : ", e);
            throw new ChainClientException("certInfos parseFrom result : " + e.getMessage());
        }

        return certInfos;
    }

    // ### 4.4 证书冻结
    // **参数说明**
    //   - payload: 证书冻结的payload
    public ResultOuterClass.TxResponse freezeCerts(Request.Payload payload, Request.EndorsementEntry[] endorsementEntries,
                                                   long rpcCallTimeout, long syncResultTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        return sendContractRequest(payload, endorsementEntries, rpcCallTimeout, syncResultTimeout);
    }

    // ### 4.5 证书解冻
    // **参数说明**
    //   - - payload: 证书解冻的payload
    public ResultOuterClass.TxResponse unfreezeCerts(Request.Payload payload, Request.EndorsementEntry[] endorsementEntries,
                                                   long rpcCallTimeout, long syncResultTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        return sendContractRequest(payload, endorsementEntries, rpcCallTimeout, syncResultTimeout);
    }

    // ### 4.6 证书吊销
    // **参数说明**
    //   - payload: 证书注销的payload
    public ResultOuterClass.TxResponse revokeCerts(Request.Payload payload, Request.EndorsementEntry[] endorsementEntries,
                                                     long rpcCallTimeout, long syncResultTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        return sendContractRequest(payload, endorsementEntries, rpcCallTimeout, syncResultTimeout);
    }

    // ### 4.7 证书操作payload生成
    // **参数说明**
    //   - method: 证书操作方法
    //   - params: 参数
    public Request.Payload createCertManagePayload(String method, Map<String, byte[]> params) throws ChainMakerCryptoSuiteException {
        return createPayload("", Request.TxType.INVOKE_CONTRACT,
                SystemContract.CERT_MANAGE.toString(), method, params, DEFAULT_SEQ);
    }

    // ### 4.8 证书删除payload生成
    // **参数说明**
    //   - certHashes: 证书Hash列表
    public Request.Payload createCertDeletePayload(String[] certHashes) throws ChainMakerCryptoSuiteException {

        Map<String, byte[]> params = new HashMap<>();
        if (certHashes.length > 0) {
            params.put(KEYCERTHASHS, Utils.joinList(certHashes).getBytes());
        }

        return createCertManagePayload(CertManage.CertManageFunction.CERTS_DELETE.toString(), params);
    }

    // ### 4.9 证书冻结payload生成
    // **参数说明**
    //   - certHashes: 证书Hash列表
    public Request.Payload createCertFreezePayload(String[] certHashes) throws ChainMakerCryptoSuiteException {

        Map<String, byte[]> params = new HashMap<>();
        if (certHashes.length > 0) {
            params.put(KEYCERTS, Utils.joinList(certHashes).getBytes());
        }

        return createCertManagePayload(CertManage.CertManageFunction.CERTS_FREEZE.toString(), params);
    }

    // ### 4.10 证书解冻payload生成
    // **参数说明**
    //   - certHashes: 证书Hash列表
    public Request.Payload createPayloadOfUnfreezeCerts(String[] certHashes) throws ChainMakerCryptoSuiteException {

        Map<String, byte[]> params = new HashMap<>();
        if (certHashes.length > 0) {
            params.put(KEYCERTS, Utils.joinList(certHashes).getBytes());
        }

        return createCertManagePayload(CertManage.CertManageFunction.CERTS_UNFREEZE.toString(), params);
    }

    // ### 4.12 创建用户证书吊销payload
    // **参数说明**
    //   - certCrl: 吊销的证书列表
    public Request.Payload createPayloadOfRevokeCerts(String certCrl) throws ChainMakerCryptoSuiteException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(KEYCERTCRL, certCrl.getBytes());

        return createCertManagePayload(CertManage.CertManageFunction.CERTS_REVOKE.toString(), params);
    }

    // ## 5 消息订阅接口
    // ### 5.1 区块订阅
    // **参数说明**
    //   - startBlock: 订阅起始区块高度，表示订阅实时最新区块
    //   - endBlock: 订阅结束区块高度，若为-1，表示订阅实时最新区块
    //   - withRwSet: 是否返回读写集
    //   - onlyHeader: 是否只返回区块头
    public void subscribeBlock(long startBlock, long endBlock, boolean withRwSet, boolean onlyHeader,
                               StreamObserver<ResultOuterClass.SubscribeResult> blockStreamObserver)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(Subscribe.SubscribeBlock.Parameter.START_BLOCK.toString(), Utils.longToByteLittleEndian(startBlock));
        params.put(Subscribe.SubscribeBlock.Parameter.END_BLOCK.toString(), Utils.longToByteLittleEndian(endBlock));
        params.put(Subscribe.SubscribeBlock.Parameter.WITH_RWSET.toString(), String.valueOf(withRwSet).getBytes());
        params.put(Subscribe.SubscribeBlock.Parameter.ONLY_HEADER.toString(), String.valueOf(onlyHeader).getBytes());

        Request.Payload payload = createPayload("", Request.TxType.SUBSCRIBE, SystemContract.SUBSCRIBE_MANAGE.toString(),
                Subscribe.SubscribeFunction.SUBSCRIBE_BLOCK.toString(), params, DEFAULT_SEQ);
        subscribe(payload, blockStreamObserver);
    }

    // ### 5.2 交易订阅
    // **参数说明**
    //   - startBlock: 订阅起始区块高度，表示订阅实时最新区块
    //   - endBlock: 订阅结束区块高度，若为-1，表示订阅实时最新区块
    //   - contractName: 订阅合约名
    //   - txIds: 订阅txId列表，若为空，表示订阅所有txId
    public void subscribeTx(long startBlock, long endBlock, String contractName, String[] txIds,
                            StreamObserver<ResultOuterClass.SubscribeResult> txStreamObserver)
            throws ChainMakerCryptoSuiteException, ChainClientException {

        Map<String, byte[]> params = new HashMap<>();
        params.put(Subscribe.SubscribeTx.Parameter.START_BLOCK.toString(), Utils.longToByteLittleEndian(startBlock));
        params.put(Subscribe.SubscribeTx.Parameter.END_BLOCK.toString(), Utils.longToByteLittleEndian(endBlock));
        params.put(Subscribe.SubscribeTx.Parameter.CONTRACT_NAME.toString(), contractName.getBytes());
        if (txIds.length > 0) {
            params.put(Subscribe.SubscribeTx.Parameter.TX_IDS.toString(), Utils.joinList(txIds).getBytes());
        }
        Request.Payload payload = createPayload("", Request.TxType.SUBSCRIBE, SystemContract.SUBSCRIBE_MANAGE.toString(),
                Subscribe.SubscribeFunction.SUBSCRIBE_TX.toString(), params, DEFAULT_SEQ);
        subscribe(payload, txStreamObserver);
    }

    // ### 5.3 事件订阅
    // **参数说明**
    //   - topic: 订阅话题
    //   - contractName: 订阅合约名
    public void subscribeContractEvent(long startBlock, long endBlock, String topic, String contractName,
                                       StreamObserver<ResultOuterClass.SubscribeResult> contractEventStreamObserver)
            throws ChainClientException, ChainMakerCryptoSuiteException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(Subscribe.SubscribeContractEvent.Parameter.START_BLOCK.toString(), Utils.longToByteLittleEndian(startBlock));
        params.put(Subscribe.SubscribeContractEvent.Parameter.END_BLOCK.toString(), Utils.longToByteLittleEndian(endBlock));
        params.put(Subscribe.SubscribeContractEvent.Parameter.TOPIC.toString(), topic.getBytes());
        params.put(Subscribe.SubscribeContractEvent.Parameter.CONTRACT_NAME.toString(), contractName.getBytes());

        Request.Payload payload = createPayload("", Request.TxType.SUBSCRIBE, SystemContract.SUBSCRIBE_MANAGE.toString(),
                Subscribe.SubscribeFunction.SUBSCRIBE_CONTRACT_EVENT.toString(), params, DEFAULT_SEQ);
        subscribe(payload, contractEventStreamObserver);
    }

    // ## 6 数据归档接口
    // ### 6.1 发送数据归档请求
    //   - payload: 数据归档payload
    public ResultOuterClass.TxResponse sendArchiveBlockRequest(Request.Payload payload, long timeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        return sendRequest(payload, null, timeout);
    }

    // ### 6.2 发送归档恢复请求
    //   - payloadBytes: 归档恢复payload
    public ResultOuterClass.TxResponse sendRestoreBlockRequest(Request.Payload payload, long timeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        return sendRequest(payload, null, timeout);
    }

    // ### 6.3 数据归档payload生成
    // **参数说明**
    //   - targetBlockHeight: 归档区块高度
    public Request.Payload createArchiveBlockPayload(long targetBlockHeight) throws ChainMakerCryptoSuiteException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(Archive.ArchiveBlock.Parameter.BLOCK_HEIGHT.toString(), Utils.longToByteLittleEndian(targetBlockHeight));

        return createPayload("", Request.TxType.ARCHIVE,
                SystemContract.ARCHIVE_MANAGE.toString(), Archive.ArchiveFunction.ARCHIVE_BLOCK.toString(), params, DEFAULT_SEQ);
    }

    // ### 6.4 归档恢复payload生成
    // **参数说明**
    //   - fullBlock: 归档恢复数据
    public Request.Payload createRestoreBlockPayload(byte[] fullBlock) throws ChainMakerCryptoSuiteException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(Archive.RestoreBlock.Parameter.FULL_BLOCK.toString(), fullBlock);

        return createPayload("", Request.TxType.ARCHIVE,
                SystemContract.ARCHIVE_MANAGE.toString(), Archive.ArchiveFunction.RESTORE_BLOCK.toString(), params, DEFAULT_SEQ);
    }

    // ### 6.5 获取归档数据
    //   - targetBlockHeight: 归档区块
    public Store.BlockWithRWSet getArchivedFullBlockByHeight(long blockHeight)
            throws ChainClientException {
        return getFromArchiveStore(blockHeight);
    }

    // ### 6.6 获取归档区块信息
    //   - targetBlockHeight: 归档区块
    //   - withRWSet: 是否获取读写集
    public ChainmakerBlock.BlockInfo getArchivedBlockByHeight(long blockHeight, boolean withRWSet)
            throws ChainClientException {
        Store.BlockWithRWSet fullBlock = getFromArchiveStore(blockHeight);

        ChainmakerBlock.BlockInfo blockInfo = ChainmakerBlock.BlockInfo.newBuilder().setBlock(fullBlock.getBlock()).build();
        ChainmakerBlock.BlockInfo.Builder blockInfoBuilder = blockInfo.toBuilder();
        if (withRWSet) {
            blockInfoBuilder.addAllRwsetList(blockInfo.getRwsetListList());
        }
        return blockInfoBuilder.build();
    }

    // ## 7 公钥身份类接口
    // ### 7.1 构造添加公钥身份请求
    // **参数说明**
    //   - pubkey: 公钥信息
    //   - orgId: 组织id
    //   - role:   角色，支持client,light,common
    public Request.Payload createPubkeyAddPayload(String pubkey, String orgId, String role) throws ChainMakerCryptoSuiteException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(KEY_PUBKEY, pubkey.getBytes());
        params.put(KEY_PUBKEY_ORG_ID, orgId.getBytes());
        params.put(KEY_PUBKEY_ROLE, role.getBytes());
        return createPayload("", Request.TxType.INVOKE_CONTRACT,
                SystemContract.PUBKEY_MANAGE.toString(), PubkeyManage.PubkeyManageFunction.PUBKEY_ADD.toString(), params, DEFAULT_SEQ);
    }

    // ### 7.2 构造删除公钥身份请求
    // **参数说明**
    //   - pubkey: 公钥信息
    //   - orgId: 组织id
    public Request.Payload createPubkeyDelPayload(String pubkey, String orgId) throws ChainMakerCryptoSuiteException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(KEY_PUBKEY, pubkey.getBytes());
        params.put(KEY_PUBKEY_ORG_ID, orgId.getBytes());
        return createPayload("", Request.TxType.INVOKE_CONTRACT,
                SystemContract.PUBKEY_MANAGE.toString(), PubkeyManage.PubkeyManageFunction.PUBKEY_DELETE.toString(), params, DEFAULT_SEQ);
    }

    // ### 7.3 构造查询公钥身份请求
    // **参数说明**
    //   - pubkey: 公钥信息
    public Request.Payload createPubkeyQueryPayload(String pubkey) throws ChainMakerCryptoSuiteException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(KEY_PUBKEY, pubkey.getBytes());
        return createPayload("", TxType.QUERY_CONTRACT,
                SystemContract.PUBKEY_MANAGE.toString(), PubkeyManage.PubkeyManageFunction.PUBKEY_QUERY.toString(), params, DEFAULT_SEQ);
    }

    // ### 7.4 发送公钥身份管理请求（添加、删除）
    // **参数说明**
    //   - payload: 合约内容
    //   - endorsementEntries: 带签名的合约内容
    //   - rpcCallTimeout: 调用rcp接口超时时间, 单位：毫秒
    //   - syncResultTimeout: 同步获取执行结果超时时间，小于等于0代表不等待执行结果，直接返回（返回信息里包含交易ID），单位：毫秒
    public ResultOuterClass.TxResponse sendPubkeyManageRequest(Request.Payload payload, Request.EndorsementEntry[] endorsementEntries,
                                                               long rpcCallTimeout, long syncResultTimeout) throws ChainClientException, ChainMakerCryptoSuiteException {

        return sendContractRequest(payload, endorsementEntries, rpcCallTimeout, syncResultTimeout);
    }

    // ## 8 多签类接口
    // ### 8.1 发起多签请求
    //   - payload: 多签payload
    public ResultOuterClass.TxResponse multiSignContractReq(Request.Payload payload, long rpcCallTimeout)
            throws ChainClientException, ChainMakerCryptoSuiteException {
        return proposalRequest(payload, null, rpcCallTimeout);
    }

    // ### 8.2 发起多签投票
    //   - payload: 多签payload
    //   - endorsementEntry: 多签信息
    public ResultOuterClass.TxResponse multiSignContractVote(Request.Payload payload, Request.EndorsementEntry endorsementEntry, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        MultiSign.MultiSignVoteInfo.Builder multiSignVoteInfoBuilder = MultiSign.MultiSignVoteInfo.newBuilder();
        multiSignVoteInfoBuilder.setEndorsement(endorsementEntry);
        multiSignVoteInfoBuilder.setVote(MultiSign.VoteStatus.AGREE);
        Map<String, byte[]> params = new HashMap<>();
        params.put(MultiSign.MultiVote.Parameter.VOTE_INFO.toString(), multiSignVoteInfoBuilder.build().toByteArray());
        params.put(MultiSign.MultiVote.Parameter.TX_ID.toString(), payload.getTxId().getBytes());
        Request.Payload multiSignVotePayload = createMultiSignVotePayload(params);
        return proposalRequest(multiSignVotePayload, null, rpcCallTimeout);
    }

    // ### 8.3 多签查询
    //   - txId: 交易id
    public ResultOuterClass.TxResponse multiSignContractQuery(String txId, long rpcCallTimeout) throws ChainMakerCryptoSuiteException, ChainClientException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(MultiSign.MultiVote.Parameter.TX_ID.toString(), txId.getBytes());
        Request.Payload payload = createMultiSignQueryPayload(params);
        return proposalRequest(payload, null, rpcCallTimeout);
    }

    // ### 8.4 创建多签请求payload
    //   - params: 多签参数
    public Request.Payload createMultiSignReqPayload(Map<String, byte[]> params) throws ChainMakerCryptoSuiteException {
        return createPayload("", Request.TxType.INVOKE_CONTRACT,
                SystemContract.MULTI_SIGN.toString(), MultiSign.MultiSignFunction.REQ.toString(), params, DEFAULT_SEQ);
    }

    // ### 8.5 创建多签投票payload
    //   - params: 多签参数
    public Request.Payload createMultiSignVotePayload(Map<String, byte[]> params) throws ChainMakerCryptoSuiteException {
        return createPayload("", Request.TxType.INVOKE_CONTRACT,
                SystemContract.MULTI_SIGN.toString(), MultiSign.MultiSignFunction.VOTE.toString(), params, DEFAULT_SEQ);
    }

    // ### 8.6 创建多签查询payload
    //   - params: 多签参数
    public Request.Payload createMultiSignQueryPayload(Map<String, byte[]> params) throws ChainMakerCryptoSuiteException {
        return createPayload("", Request.TxType.INVOKE_CONTRACT,
                SystemContract.MULTI_SIGN.toString(), MultiSign.MultiSignFunction.QUERY.toString(), params, DEFAULT_SEQ);
    }

    // ## 9 管理类接口
    // ### 9.1 SDK停止接口：关闭连接池连接，释放资源
    public void stop()  {
        connectionPool.stop();
    }

    // ### 9.2 获取链版本
    public String getChainMakerServerVersion(long timeout) throws ChainClientException {
        RpcServiceClient rpcServiceClient = connectionPool.getConnection();
        if (rpcServiceClient == null) {
            logger.error("all connections no Idle or Ready");
            throw new ChainClientException("all connections no Idle or Ready, please reSet connection count");
        }

        ChainMakerVersionResponse response;
        ChainMakerVersionRequest.Builder chainMakerVersionRequest = ChainMakerVersionRequest.newBuilder();

        try {
            response = rpcServiceClient.getRpcNodeFutureStub().getChainMakerVersion(chainMakerVersionRequest.build()).get(timeout, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            logger.error("connect to peer error : ", e);
            throw new ChainClientException("connect to peer error : " + e.getMessage());
        }

        if (response.getCode() != SUCCESS) {
            logger.error("get chain version failed : " + response.getMessage());
            throw new ChainClientException("get chain version failed : " + response.getMessage());
        }
        return response.getVersion();
    }

    // ### 9.3 更新链配置
    public CheckNewBlockChainConfigResponse checkNewBlockChainConfig(long timeout) throws ChainClientException {
        RpcServiceClient rpcServiceClient = connectionPool.getConnection();
        if (rpcServiceClient == null) {
            logger.error("all connections no Idle or Ready");
            throw new ChainClientException("all connections no Idle or Ready, please reSet connection count");
        }
        CheckNewBlockChainConfigResponse response;
        CheckNewBlockChainConfigRequest.Builder checkNewBlockChainConfigRequest = CheckNewBlockChainConfigRequest.newBuilder();

        try {
            response = rpcServiceClient.getRpcNodeFutureStub().checkNewBlockChainConfig(checkNewBlockChainConfigRequest.build()).get(timeout, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            logger.error("connect to peer error : ", e);
            throw new ChainClientException("connect to peer error : " + e.getMessage());
        }

        if (response.getCode() != SUCCESS) {
            logger.error("check new block chain config failed : " + response.getMessage());
            throw new ChainClientException("check new block chain config failed : " + response.getMessage());
        }

        return response;
    }

    // ## 10 gas管理相关接口
    // ### 10.1 构造设置gas管理员payload
    // **参数说明**
    //   - address: gas管理员的地址
    public Request.Payload createSetGasAdminPayload(String address)
            throws ChainMakerCryptoSuiteException, UtilsException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(KEY_GASADDRESSKEY, address.getBytes());
        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.ACCOUNT_MANAGER.toString(),
                AccountManager.GasAccountFunction.SET_ADMIN.toString(), params, DEFAULT_SEQ);
    }

    // ### 10.2 查询gas管理员
    // **参数说明**
    //   - rpcCallTimeout: 调用rpc接口超时时间, 单位：毫秒
    public String getGasAdmin(long rpcCallTimeout) throws ChainClientException {
        ResultOuterClass.TxResponse resp;
        try {
            Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.ACCOUNT_MANAGER.toString(),
                    AccountManager.GasAccountFunction.GET_ADMIN.toString(), null, DEFAULT_SEQ);
            resp = proposalRequest(payload, null, rpcCallTimeout);
            checkProposalRequestResp(resp, true);
        } catch (Exception e) {
            logger.error("[SDK] begin to QUERY system contract, method:", e);
            throw new ChainClientException("Gas Admin error:" + e.getMessage());
        }
        return resp.getContractResult().getResult().toStringUtf8();
    }

    // ### 10.3 构造充值gas账户payload
    // **参数说明**
    //   - rechargeGasList: 一个gas账户充值指定gas数量
    public Request.Payload createRechargeGasPayload(AccountManager.RechargeGas[] rechargeGasList)
            throws ChainMakerCryptoSuiteException {
        AccountManager.RechargeGasReq.Builder rechargeGasReqBuilder = AccountManager.RechargeGasReq.newBuilder();
        rechargeGasReqBuilder.addAllBatchRechargeGas(Arrays.asList(rechargeGasList.clone()));

        Map<String, byte[]> params = new HashMap<>();
        params.put(Key_GASBATCHRECHARGE, rechargeGasReqBuilder.build().toByteArray());
        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.ACCOUNT_MANAGER.toString(),
                AccountManager.GasAccountFunction.RECHARGE_GAS.toString(), params, DEFAULT_SEQ);
    }

    // ### 10.4 查询gas账户余额（根据公钥）
    // **参数说明**
    //   - address: 查询gas余额的账户地址
    //   - rpcCallTimeout: 调用rpc接口超时时间, 单位：毫秒
    public long getGasBalance(String address, long rpcCallTimeout)
            throws ChainClientException, ChainMakerCryptoSuiteException, UtilsException {

        Map<String, byte[]> params = new HashMap<>();
        params.put(KEY_GASADDRESSKEY, address.getBytes());

        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.ACCOUNT_MANAGER.toString(),
            AccountManager.GasAccountFunction.GET_BALANCE.toString(), params, DEFAULT_SEQ);
        ResultOuterClass.TxResponse resp = proposalRequest(payload, null, rpcCallTimeout);
        checkProposalRequestResp(resp, true);
        return Long.parseLong(resp.getContractResult().getResult().toStringUtf8());
    }

    // ### 10.5 构造 退还gas账户的gas payload
    // **参数说明**
    //   - address: 退还gas的账户地址
    //   - amount: 退还gas的数量
    public Request.Payload createRefundGasPayload(String address, long amount)
            throws ChainMakerCryptoSuiteException {
        if(amount <= 0){
            logger.error("amount must > 0");
        }
        Map<String, byte[]> params = new HashMap<>();
        params.put(KEY_GASADDRESSKEY, address.getBytes());
        params.put(Key_GASCHARGEGASAMOUNT, String.valueOf(amount).getBytes());

        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.ACCOUNT_MANAGER.toString(),
                AccountManager.GasAccountFunction.REFUND_GAS.toString(), params, DEFAULT_SEQ);
    }

    // ### 10.6 构造 冻结指定gas账户 payload
    // **参数说明**
    //   - address: 冻结指定gas账户的账户地址
    public Request.Payload createFrozenGasAccountPayload(String address)
            throws ChainMakerCryptoSuiteException, UtilsException {

        Map<String, byte[]> params = new HashMap<>();
        params.put(KEY_GASADDRESSKEY, address.getBytes());

        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.ACCOUNT_MANAGER.toString(),
                AccountManager.GasAccountFunction.FROZEN_ACCOUNT.toString(), params, DEFAULT_SEQ);
    }

    // ### 10.7 构造 解冻指定gas账户 payload
    // **参数说明**
    //   - address: 解冻指定gas账户的账户地址
    public Request.Payload createUnfrozenGasAccountPayload(String address)
            throws ChainMakerCryptoSuiteException, UtilsException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(KEY_GASADDRESSKEY, address.getBytes());

        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.ACCOUNT_MANAGER.toString(),
                AccountManager.GasAccountFunction.UNFROZEN_ACCOUNT.toString(), params, DEFAULT_SEQ);
    }

    // ### 10.8 查询gas账户的状态
    // **参数说明**
    //   - address: 指定gas账户的账户地址
    //   - rpcCallTimeout: 调用rpc接口超时时间, 单位：毫秒
    // **返回值说明**
    //   - boolean: true表示账号未被冻结，false表示账号已被冻结
    public boolean getGasAccountStatus(String address, long rpcCallTimeout)
            throws ChainClientException, ChainMakerCryptoSuiteException, UtilsException {
        ResultOuterClass.TxResponse resp;

        Map<String, byte[]> params = new HashMap<>();
        params.put(KEY_GASADDRESSKEY, address.getBytes());

        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.ACCOUNT_MANAGER.toString(),
                AccountManager.GasAccountFunction.ACCOUNT_STATUS.toString(), params, DEFAULT_SEQ);
        resp = proposalRequest(payload, null, rpcCallTimeout);
        checkProposalRequestResp(resp, true);
        return resp.getContractResult().getResult().toStringUtf8().equals("0");
    }

    // ### 10.9 发送gas管理类请求
    // **参数说明**
    //   - payload: 交易payload
    //   - endorsementEntries: 背书签名信息列表
    //   - rpcCallTimeout: 超时时间，单位：s，若传入-1，将使用默认超时时间：10s
    //   - syncResultTimeout: 是否同步获取交易执行结果
    //            当为true时，若成功调用，common.TxResponse.ContractResult.Result为common.TransactionInfo
    //            当为false时，若成功调用，common.TxResponse.ContractResult为空，可以通过common.TxResponse.TxId查询交易结果
    public ResultOuterClass.TxResponse sendGasManageRequest(Request.Payload payload, Request.EndorsementEntry[] endorsementEntries,
                                                long rpcCallTimeout, long syncResultTimeout)
    throws ChainClientException, ChainMakerCryptoSuiteException {
        return sendContractRequest(payload, endorsementEntries, rpcCallTimeout, syncResultTimeout);
    }

    // ### 10.10 为payload添加gas limit
    // **参数说明**
    //   - payload: 交易payload
    //   - limit: gas limit
    public Request.Payload attachGasLimit(Request.Payload payload, Request.Limit limit) {
        Request.Payload.Builder payloadBuilder = payload.toBuilder();
        payloadBuilder.setLimit(limit);
        payload = payloadBuilder.build();
        return payload;
    }

    // ### 10.11 启用或停用Gas计费开关payload生成
    // **参数说明**
    //   - rpcCallTimeout: 超时时间，单位：s，若传入-1，将使用默认超时时间：10s
    public Request.Payload createChainConfigEnableOrDisableGasPayload(long rpcCallTimeout)
    throws ChainClientException, ChainMakerCryptoSuiteException {
        long sequence = getChainConfigSequence(rpcCallTimeout);
        return createPayload("", Request.TxType.INVOKE_CONTRACT, SystemContract.CHAIN_CONFIG.toString(),
                ChainConfig.ChainConfigFunction.ENABLE_OR_DISABLE_GAS.toString(), null, sequence + 1);
    }

    // ## 11 别名相关接口
    // ### 11.1 添加别名
    // **参数说明**
    //   - rpcCallTimeout: 超时时间，单位：s，若传入-1，将使用默认超时时间：10s
    public ResultOuterClass.TxResponse addAlias(long rpcCallTimeout) throws ChainMakerCryptoSuiteException,
            ChainClientException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(KEY_ALIAS, clientUser.getAlias().getBytes());

        Request.Payload payload = createCertManagePayload(CertManageFunction.CERT_ALIAS_ADD.toString(), params);
        ResultOuterClass.TxResponse txResponse = sendContractRequest(payload, null, rpcCallTimeout, DEFAULT_SYNC_RESULT_TIMEOUT);

        checkProposalRequestResp(txResponse, true);

        ResultOuterClass.TxResponse.Builder txResponseBuilder = txResponse.toBuilder();
        txResponseBuilder.setContractResult(ResultOuterClass.ContractResult.newBuilder().setResult(ByteString.copyFrom(clientUser.getAlias().getBytes())));

        return txResponseBuilder.build();
    }

    // ### 11.2 构造更新别名payload
    // **参数说明**
    //   - alias: 要更新的别名
    //   - certPEM: 对应的证书
    public Request.Payload createUpdateAliasPayload(String alias, String certPem)
            throws ChainMakerCryptoSuiteException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(KEY_ALIAS, alias.getBytes());
        params.put(KEY_CERT, certPem.getBytes());

        return createCertManagePayload(CertManageFunction.CERT_ALIAS_UPDATE.toString(), params);
    }

    // ### 11.3 发起更新别名交易
    // **参数说明**
    //   - payload: 待签名的payload
    //   - endorsementEntries: 背书签名信息列表
    //   - rpcCallTimeout: 超时时间，单位：s，若传入-1，将使用默认超时时间：10s
    public ResultOuterClass.TxResponse updateAlias(Request.Payload payload, Request.EndorsementEntry[] endorsementEntries,
            long rpcCallTimeout) throws ChainClientException, ChainMakerCryptoSuiteException {

        return sendContractRequest(payload, endorsementEntries, rpcCallTimeout, -1);
    }

    // ### 11.4 查询别名详情交易
    // **参数说明**
    //   - aliasList: 要查询的别名列表
    //   - rpcCallTimeout: 超时时间，单位：s，若传入-1，将使用默认超时时间：10s
    public ResultOuterClass.AliasInfos queryAlias(String[] aliasList, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(KEY_ALIASES, Utils.joinList(aliasList).getBytes());

        Request.Payload payload = createPayload("", TxType.QUERY_CONTRACT,
                SystemContract.CERT_MANAGE.toString(), CertManageFunction.CERTS_ALIAS_QUERY.toString(), params, DEFAULT_SEQ);

        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);

        checkProposalRequestResp(txResponse, true);

        ResultOuterClass.AliasInfos aliasInfos;
        try {
            aliasInfos = ResultOuterClass.AliasInfos.parseFrom(txResponse.getContractResult().getResult());
        } catch (InvalidProtocolBufferException e) {
            logger.error("aliasInfo parseFrom result : ", e);
            throw new ChainClientException("aliasInfo parseFrom result : " + e.getMessage());
        }
        return aliasInfos;
    }

    // ### 11.5 生成删除别名payload
    // **参数说明**
    //   - aliasList: 要删除的别名列表
    //   - rpcCallTimeout: 超时时间，单位：s，若传入-1，将使用默认超时时间：10s
    public Request.Payload createAliasDeletePayload(String[] aliasList) throws ChainMakerCryptoSuiteException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(KEY_ALIASES, Utils.joinList(aliasList).getBytes());

        return createCertManagePayload(CertManageFunction.CERTS_ALIAS_DELETE.toString(), params);
    }

    // ### 11.6 发起更新别名交易
    // **参数说明**
    //   - payload: 待签名的payload
    //   - endorsementEntries: 背书签名信息列表
    //   - rpcCallTimeout: 超时时间，单位：s，若传入-1，将使用默认超时时间：10s
    //   - syncResultTimeout: 是否同步获取交易执行结果
    public ResultOuterClass.TxResponse deleteAlias(Request.Payload payload, Request.EndorsementEntry[] endorsementEntries,
            long rpcCallTimeout, long syncResultTimeout) throws ChainClientException, ChainMakerCryptoSuiteException {

        return sendContractRequest(payload, endorsementEntries, rpcCallTimeout, syncResultTimeout);
    }

    private Request.TxRequest createTxRequest(Request.Payload payload, Request.EndorsementEntry[] endorsementEntries)
            throws ChainMakerCryptoSuiteException {

        MemberOuterClass.Member sender;
        Request.EndorsementEntry.Builder endorsementEntryBuilder;

        if (clientUser.getAuthType().equals(AuthType.PermissionedWithCert.getMsg())) {
            if (isEnabledCertHash && clientUser.getCertHash() != null && clientUser.getCertHash().length > 0) {
                sender = MemberOuterClass.Member.newBuilder()
                        .setOrgId(clientUser.getOrgId())
                        .setMemberInfo(ByteString.copyFrom(clientUser.getCertHash()))
                        .setMemberType(MemberOuterClass.MemberType.CERT_HASH)
                        .build();
            } else if (isEnabledAlias && clientUser.getAlias() != null && clientUser.getAlias().length() > 0) {
                sender = MemberOuterClass.Member.newBuilder()
                        .setOrgId(clientUser.getOrgId())
                        .setMemberInfo(ByteString.copyFrom(clientUser.getAlias().getBytes()))
                        .setMemberType(MemberType.ALIAS)
                        .build();
            } else {
                sender = MemberOuterClass.Member.newBuilder()
                        .setOrgId(clientUser.getOrgId())
                        .setMemberInfo(ByteString.copyFrom(clientUser.getCertBytes()))
                        .setMemberType(MemberOuterClass.MemberType.CERT)
                        .build();
            }
            endorsementEntryBuilder = Request.EndorsementEntry.newBuilder()
                    .setSigner(sender)
                    .setSignature(ByteString.copyFrom(clientUser.getCryptoSuite().sign(clientUser.getPrivateKey(), payload.toByteArray())));

        } else {
            sender = MemberOuterClass.Member.newBuilder()
                    .setOrgId(clientUser.getOrgId())
                    .setMemberInfo(ByteString.copyFrom(clientUser.getPukBytes()))
                    .setMemberType(MemberOuterClass.MemberType.PUBLIC_KEY)
                    .build();
            endorsementEntryBuilder = Request.EndorsementEntry.newBuilder()
                    .setSigner(sender)
                    .setSignature(ByteString.copyFrom(clientUser.getCryptoSuite().rsaSign(clientUser.getPrivateKey(), payload.toByteArray())));
        }

        Request.TxRequest.Builder txRequestBuilder = Request.TxRequest.newBuilder()
                .setPayload(payload)
                .setSender(endorsementEntryBuilder);
        if (endorsementEntries != null) {
            txRequestBuilder.addAllEndorsers(Arrays.asList(endorsementEntries.clone()));
        }
        return txRequestBuilder.build();
    }

    private ResultOuterClass.TxResponse sendTxRequest(Request.TxRequest signedRequest, long timeout) throws ChainClientException {
        ResultOuterClass.TxResponse txResponse;
        RpcServiceClient rpcServiceClient = connectionPool.getConnection();
        if (rpcServiceClient == null) {
            logger.error("all connections no Idle or Ready");
            throw new ChainClientException("all connections no Idle or Ready, please reSet connection count");
        }
        try {
            txResponse = rpcServiceClient.getRpcNodeFutureStub().sendRequest(signedRequest)
                    .get(timeout, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            logger.error("connect to peer error : ", e);
            throw new ChainClientException("connect to peer error : " + e.getMessage());
        }

        return txResponse;
    }

    public ChainmakerBlock.BlockInfo getArchivedBlockByTxId(String txId, boolean withRWSet, long timeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        long blockHeight = getBlockHeightByTxId(txId, timeout);
        return getArchivedBlockByHeight(blockHeight, withRWSet);
    }

    public ChainmakerBlock.BlockInfo getArchivedBlockByHash(String blockHash, boolean withRWSet, long timeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        long blockHeight = getBlockHeightByBlockHash(blockHash, timeout);
        return getArchivedBlockByHeight(blockHeight, withRWSet);
    }

    public ChainmakerTransaction.TransactionInfo getArchivedTxByTxId(String txId, long timeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {
        long blockHeight = getBlockHeightByTxId(txId, timeout);
        ChainmakerBlock.BlockInfo blockInfo = getArchivedBlockByHeight(blockHeight, false);
        for (int i = 0; i < blockInfo.getBlock().getTxsList().size(); i++) {
            ChainmakerTransaction.Transaction tx = blockInfo.getBlock().getTxs(i);
            if (tx.getPayload().getTxId().equals(txId)) {
                return ChainmakerTransaction.TransactionInfo.newBuilder().setTransaction(tx)
                        .setBlockHeight(blockInfo.getBlock().getHeader().getBlockHeight())
                        .setBlockHash(blockInfo.getBlock().getHeader().getBlockHash())
                        .setTxIndex(i).build();
            }
        }
        return null;
    }

    private long getBlockHeight(String txId, String blockHash, long rpcCallTimeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {

        Map<String, byte[]> params = new HashMap<>();
        String method = "";

        if (txId != null && !txId.equals("")) {
            method = ChainQuery.ChainQueryFunction.GET_BLOCK_HEIGHT_BY_TX_ID.toString();
            params.put(TX_ID, txId.getBytes());
        } else if (blockHash != null && !blockHash.equals("")) {
            method = ChainQuery.ChainQueryFunction.GET_BLOCK_HEIGHT_BY_HASH.toString();
            params.put(BLOCK_HASH, blockHash.getBytes());
        }
        Request.Payload payload = createPayload("", Request.TxType.QUERY_CONTRACT, SystemContract.CHAIN_QUERY.toString(),
                method, params, 0);

        ResultOuterClass.TxResponse txResponse = proposalRequest(payload, null, rpcCallTimeout);

        return Integer.parseInt(txResponse.getContractResult().getResult().toStringUtf8());
    }

    private Request.Payload createContractManagePayload(String contractName, String method) throws ChainMakerCryptoSuiteException {
        Map<String, byte[]> params = new HashMap<>();
        params.put(ContractManage.GetContractInfo.Parameter.CONTRACT_NAME.toString(), contractName.getBytes());

        return createPayload("", Request.TxType.INVOKE_CONTRACT,
                SystemContract.CONTRACT_MANAGE.toString(), method, params, DEFAULT_SEQ);
    }

    private Request.Payload createContractManageWithByteCodePayload(String contractName, String method, String version, byte[] byteCode,
                                                        ContractOuterClass.RuntimeType runtime, Map<String, byte[]> params)
            throws ChainMakerCryptoSuiteException {

        Request.Payload payload = createPayload("", Request.TxType.INVOKE_CONTRACT,
                SystemContract.CONTRACT_MANAGE.toString(), method, params, DEFAULT_SEQ);

        Request.Payload.Builder payloadBuilder = payload.toBuilder();

        payloadBuilder.addParameters(Request.KeyValuePair.newBuilder()
                .setKey(ContractManage.InitContract.Parameter.CONTRACT_NAME.toString())
                .setValue(ByteString.copyFromUtf8(contractName)));

        payloadBuilder.addParameters(Request.KeyValuePair.newBuilder()
                .setKey(ContractManage.InitContract.Parameter.CONTRACT_VERSION.toString())
                .setValue(ByteString.copyFromUtf8(version)));

        payloadBuilder.addParameters(Request.KeyValuePair.newBuilder()
                .setKey(ContractManage.InitContract.Parameter.CONTRACT_RUNTIME_TYPE.toString())
                .setValue(ByteString.copyFromUtf8(runtime.toString())));

        payloadBuilder.addParameters(Request.KeyValuePair.newBuilder()
                .setKey(ContractManage.InitContract.Parameter.CONTRACT_BYTECODE.toString())
                .setValue(ByteString.copyFrom(byteCode)));

        return payloadBuilder.build();
    }

    private Request.Payload createNativeContractAccessPayload(String method, String[] accessContractList) throws ChainMakerCryptoSuiteException {
        String jsonString = JSON.toJSONString(accessContractList);
        Map<String, byte[]> params = new HashMap<>();
        params.put(ContractManage.ContractAccess.Parameter.NATIVE_CONTRACT_NAME.toString(), jsonString.getBytes());
        return createPayload("", Request.TxType.INVOKE_CONTRACT,
                SystemContract.CONTRACT_MANAGE.toString(), method, params, DEFAULT_SEQ);
    }

    private Request.Payload createPayload(String txId, Request.TxType txType, String contractName, String method,
                                          Map<String, byte[]> params, long seq) throws ChainMakerCryptoSuiteException {

        if (txId == null || txId.equals("")) {
            txId = Utils.generateTxId(ByteString.copyFrom(UUID.randomUUID().toString().getBytes())
                    .concat(ByteString.copyFrom(UUID.randomUUID().toString().getBytes())), clientUser.getCryptoSuite());
        }

        Request.Payload.Builder payloadBuilder = Request.Payload.newBuilder()
                .setChainId(chainId)
                .setTxType(txType)
                .setTxId(txId)
                .setTimestamp(Utils.getCurrentTimeSeconds())
                .setContractName(contractName)
                .setMethod(method)
                .setSequence(seq);

        if (params != null && !params.isEmpty()) {
            params.forEach((key, value) -> payloadBuilder.addParameters(
                    Request.KeyValuePair.newBuilder().setKey(key).setValue(ByteString.copyFrom(value)).build()));
        }

        return payloadBuilder.build();
    }

    private ResultOuterClass.TxResponse proposalRequest(Request.Payload payload, Request.EndorsementEntry[] endorsementEntries,
                                                        long rpcCallTimeout) throws ChainClientException, ChainMakerCryptoSuiteException {
        return sendRequest(payload, endorsementEntries, rpcCallTimeout);
    }

    private ResultOuterClass.TxResponse sendContractRequest(Request.Payload payload, Request.EndorsementEntry[] endorsementEntries,
                                                            long rpcCallTimeout, long syncResultTimeout)
            throws ChainClientException, ChainMakerCryptoSuiteException {
        ResultOuterClass.TxResponse responseInfo  = sendRequest(payload, endorsementEntries, rpcCallTimeout);
        ResultOuterClass.TxResponse.Builder responseInfoBuilder = responseInfo.toBuilder();
        if (responseInfo.getCode() == ResultOuterClass.TxStatusCode.SUCCESS) {
            if (syncResultTimeout > 0) {
                ChainmakerTransaction.TransactionInfo transactionInfo = loopQueryResultByTxId(responseInfo.getTxId(), syncResultTimeout);
                if (transactionInfo == null || transactionInfo.getTransaction() == null || transactionInfo.getTransaction().getResult() == null) {
                    throw new ChainClientException(format("get tx by txId %s failed", responseInfo.getTxId()));
                }
                responseInfoBuilder.setContractResult(transactionInfo.getTransaction().getResult().getContractResult().toBuilder()).build();
            }
        }

        return responseInfoBuilder.build();
    }

    private ResultOuterClass.TxResponse sendRequest(Request.Payload payload, Request.EndorsementEntry[] endorsementEntries,
                                      long rpcCallTimeout) throws ChainMakerCryptoSuiteException, ChainClientException {
        return sendTxRequest(createTxRequest(payload, endorsementEntries), rpcCallTimeout);
    }

    private ChainmakerTransaction.TransactionInfo loopQueryResultByTxId(String txId, long timeout)
            throws ChainMakerCryptoSuiteException, ChainClientException {

        // get try cont from timeout, will sleep 2 seconds between queries
        long tryCount = timeout % 2000 == 0 ? timeout / 2000 : timeout / 2000 + 1;
        if (tryCount == 0) {
            tryCount++;
        }
        for (long i = 0; i < tryCount; i++) {
            ChainmakerTransaction.TransactionInfo transactionInfo = getTxByTxId(txId, timeout);
            if (transactionInfo == null || !transactionInfo.hasTransaction()) {
                try {
                    Thread.sleep(2000);
                } catch (InterruptedException e) {
                    logger.error("Thread sleep error : ", e);
                }
                continue;
            }
            return transactionInfo;
        }
        return null;
    }

    private void subscribe(Request.Payload payload, StreamObserver<ResultOuterClass.SubscribeResult> txStreamObserver)
            throws ChainClientException {
        RpcServiceClient rpcServiceClient = connectionPool.getConnection();
        if (rpcServiceClient == null) {
            logger.error("all connections no Idle or Ready");
            throw new ChainClientException("all connections no Idle or Ready, please reSet connection count");
        }
        try {
            rpcServiceClient.getRpcNodeStub().subscribe(createTxRequest(
                    payload, null), txStreamObserver);
        } catch (Exception e) {
            logger.error("subscribeTx to peer error : ", e);
            throw new ChainClientException("subscribeTx to peer error : " + e.getMessage());
        }
    }

    public Store.BlockWithRWSet getFromArchiveStore(long blockHeight)
            throws ChainClientException {
        if (archiveConfig.getType().equals("mysql")) {
            return getArchivedBlockFromMySQL(blockHeight);
        }
        return null;
    }

    public Store.BlockWithRWSet getArchivedBlockFromMySQL(long blockHeight)
            throws ChainClientException {

        String archiveDest = archiveConfig.getDest();
        String[] destList = archiveDest.split(":");

        String user = destList[0];
        String pwd = destList[1];
        String host = destList[2];
        String port = destList[3];

        try {
            Class.forName(DRIVER_NAME);
        } catch (ClassNotFoundException e) {
            logger.error(DRIVER_NAME + " class not found : ", e);
            throw new ChainClientException("class not found : " + e.getMessage());
        }
        String url = String.format("jdbc:mysql://%s:%s/%s_%s?serverTimezone=GMT", host, port, MYSQL_DBNAME_PREFIX, chainId);

        byte[] blockWithRWSetBytes = null;
        String hmac = "";

        try {
            Connection connection = DriverManager.getConnection(url, user, pwd);
            Statement statement = connection.createStatement();
            String sql = String.format("SELECT Fblock_with_rwset, Fhmac from %s_%d WHERE Fblock_height = %d",
                    MYSQL_TABLENAME_PREFIX, blockHeight / ROWS_PREBLOCKINFO_TABLE + 1, blockHeight);
            ResultSet resultSet = statement.executeQuery(sql);

            while (resultSet.next()) {
                ResultSetMetaData metaData = resultSet.getMetaData();
                for (int i = 1; i < metaData.getColumnCount() + 1; i++) {
                    if (metaData.getColumnName(i).equals("Fblock_with_rwset")) {
                        blockWithRWSetBytes = (byte[]) resultSet.getObject(i);
                    }
                    if (metaData.getColumnName(i).equals("Fhmac")) {
                        hmac = (String) resultSet.getObject(i);
                    }
                }
            }
            connection.close();
        } catch (SQLException e) {
            logger.error("sql err : ", e);
            throw new ChainClientException("sql err : " + e.getMessage());
        }

        Store.BlockWithRWSet blockWithRWSet;
        try {
            blockWithRWSet = Store.BlockWithRWSet.parseFrom(blockWithRWSetBytes);
        } catch (InvalidProtocolBufferException e) {
            logger.error("blockWithRWSet parseFrom result : ", e);
            throw new ChainClientException("blockWithRWSet parseFrom result : " + e.getMessage());
        }
        return blockWithRWSet;
    }

    public void checkProposalRequestResp(ResultOuterClass.TxResponse resp, boolean needContractResult)
            throws ChainClientException {
        if (resp.getCode() != TxStatusCode.SUCCESS) {
            throw new ChainClientException(resp.getMessage());
        }

        if (needContractResult && resp.getContractResult() == null) {
            throw new ChainClientException("contract result is nulll");
        }

        if (resp.getContractResult() != null && resp.getContractResult().getCode() != SUCCESS) {
            throw new ChainClientException(resp.getContractResult().getMessage());
        }
    }

}