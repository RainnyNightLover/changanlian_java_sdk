/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.config;

import java.security.PublicKey;

public class ChainClientConfig {

    private String chainId;

    private String orgId = "";

    private String userKeyFilePath;

    private String userCrtFilePath;

    private String userSignKeyFilePath;

    private String userSignCrtFilePath;

    private byte[] userKeyBytes;

    private byte[] userCrtBytes;

    private byte[] userSignKeyBytes;

    private byte[] userSignCrtBytes;

    private String authType = AuthType.PermissionedWithCert.getMsg();

    private int retryLimit;

    private int retryInterval;

    private CryptoConfig crypto;

    private NodeConfig[] nodes;

    private ArchiveConfig archive;

    private RpcClientConfig rpcClient;

    private PublicKey publicKey;

    private String alias;

    public void setChain_id(String chain_id) {
        this.chainId = chain_id;
    }

    public void setOrg_id(String org_id) {
        this.orgId = org_id;
    }

    public void setUser_key_file_path(String user_key_file_path) {
        this.userKeyFilePath = user_key_file_path;
    }

    public void setUser_crt_file_path(String user_crt_file_path) {
        this.userCrtFilePath = user_crt_file_path;
    }


    public void setUser_sign_key_file_path(String user_sign_key_file_path) {
        this.userSignKeyFilePath = user_sign_key_file_path;
    }

    public void setUser_sign_crt_file_path(String user_sign_crt_file_path) {
        this.userSignCrtFilePath = user_sign_crt_file_path;
    }

    public String getAuth_type() {
        return authType;
    }

    public void setAuth_type(String authType) {
        this.authType = authType;
    }

    public void setRetry_limit(int retryLimit) {
        this.retryLimit = retryLimit;
    }

    public void setRetry_interval(int retryInterval) {
        this.retryInterval = retryInterval;
    }

    public NodeConfig[] getNodes() {
        return nodes;
    }

    public void setNodes(NodeConfig[] nodes) {
        this.nodes = nodes;
    }

    public ArchiveConfig getArchive() {
        return archive;
    }

    public void setArchive(ArchiveConfig archive) {
        this.archive = archive;
    }

    public RpcClientConfig getRpc_client() {
        return rpcClient;
    }

    public void setRpc_client(RpcClientConfig rpc_client) {
        this.rpcClient = rpc_client;
    }

    public byte[] getUserKeyBytes() {
        return userKeyBytes;
    }

    public void setUserKeyBytes(byte[] userKeyBytes) {
        this.userKeyBytes = userKeyBytes;
    }

    public byte[] getUserCrtBytes() {
        return userCrtBytes;
    }

    public void setUserCrtBytes(byte[] userCrtBytes) {
        this.userCrtBytes = userCrtBytes;
    }

    public byte[] getUserSignKeyBytes() {
        return userSignKeyBytes;
    }

    public void setUserSignKeyBytes(byte[] userSingKeyBytes) {
        this.userSignKeyBytes = userSingKeyBytes;
    }

    public byte[] getUserSignCrtBytes() {
        return userSignCrtBytes;
    }

    public void setUserSignCrtBytes(byte[] userSignCrtBytes) {
        this.userSignCrtBytes = userSignCrtBytes;
    }

    public String getChainId() {
        return chainId;
    }

    public void setChainId(String chainId) {
        this.chainId = chainId;
    }

    public String getOrgId() {
        return orgId;
    }

    public void setOrgId(String orgId) {
        this.orgId = orgId;
    }

    public String getUserKeyFilePath() {
        return userKeyFilePath;
    }

    public void setUserKeyFilePath(String userKeyFilePath) {
        this.userKeyFilePath = userKeyFilePath;
    }

    public String getUserCrtFilePath() {
        return userCrtFilePath;
    }

    public void setUserCrtFilePath(String userCrtFilePath) {
        this.userCrtFilePath = userCrtFilePath;
    }

    public String getUserSignKeyFilePath() {
        return userSignKeyFilePath;
    }

    public void setUserSignKeyFilePath(String userSignKeyFilePath) {
        this.userSignKeyFilePath = userSignKeyFilePath;
    }

    public String getUserSignCrtFilePath() {
        return userSignCrtFilePath;
    }

    public void setUserSignCrtFilePath(String userSignCrtFilePath) {
        this.userSignCrtFilePath = userSignCrtFilePath;
    }

    public RpcClientConfig getRpcClient() {
        return rpcClient;
    }

    public void setRpcClient(RpcClientConfig rpcClient) {
        this.rpcClient = rpcClient;
    }

    public int getRetryLimit() {
        return retryLimit;
    }

    public void setRetryLimit(int retryLimit) {
        this.retryLimit = retryLimit;
    }

    public int getRetryInterval() {
        return retryInterval;
    }

    public void setRetryInterval(int retryInterval) {
        this.retryInterval = retryInterval;
    }

    public String getAuthType() {
        return authType;
    }

    public void setAuthType(String authType) {
        this.authType = authType;
    }

    public CryptoConfig getCrypto() {
        return crypto;
    }

    public void setCrypto(CryptoConfig crypto) {
        this.crypto = crypto;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }
}
