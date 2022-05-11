/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.chainmaker.sdk.config.ArchiveConfig;
import org.chainmaker.sdk.config.AuthType;
import org.chainmaker.sdk.config.ChainClientConfig;
import org.chainmaker.sdk.config.NodeConfig;
import org.chainmaker.sdk.config.SdkConfig;
import org.chainmaker.sdk.crypto.ChainMakerCryptoSuiteException;
import org.chainmaker.sdk.utils.CryptoUtils;
import org.chainmaker.sdk.utils.FileUtils;
import org.chainmaker.sdk.utils.UtilsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ChainManager {

    private static final Logger logger = LoggerFactory.getLogger(ChainManager.class);

    static String OPENSSL_PROVIDER = "openSSL";
    static String TLS_NEGOTIATION = "TLS";

    // chains' map
    private Map<String, ChainClient> chains = new HashMap<>();
    // for singleton mode
    private static ChainManager chainManager = new ChainManager();

    private ChainManager() {
    }

    // singleton getInstance
    public static ChainManager getInstance() {
        return chainManager;
    }

    // get a chain client from chains
    public ChainClient getChainClient(String chainId) {
        return chains.get(chainId);
    }

    public synchronized ChainClient createChainClient(SdkConfig sdkConfig)
            throws ChainClientException, RpcServiceClientException, UtilsException, ChainMakerCryptoSuiteException {
        checkConfig(sdkConfig.getChainClient());
        String chainId = sdkConfig.getChainClient().getChainId();
        ChainClientConfig chainClientConfig = sdkConfig.getChainClient();
        dealChainClientConfig(chainClientConfig);

        User clientUser;

        if (chainClientConfig.getAuthType().equals(AuthType.PermissionedWithKey.getMsg()) ||
                chainClientConfig.getAuthType().equals(AuthType.Public.getMsg())) {
            clientUser = new User(sdkConfig.getChainClient().getOrgId());
            clientUser.setPukBytes(CryptoUtils.getPemStrFromPublicKey(chainClientConfig.getPublicKey()).getBytes());
            clientUser.setPublicKey(chainClientConfig.getPublicKey());
            clientUser.setPrivateKey(CryptoUtils.getPrivateKeyFromBytes(FileUtils.getFileBytes(chainClientConfig.getUserSignKeyFilePath())));
        } else {
             clientUser = new User(sdkConfig.getChainClient().getOrgId(),
                    chainClientConfig.getUserSignKeyBytes(),
                    chainClientConfig.getUserSignCrtBytes(),
                    chainClientConfig.getUserKeyBytes(),
                    chainClientConfig.getUserCrtBytes());
             if (sdkConfig.getChainClient().getAlias() != null && sdkConfig.getChainClient().getAlias().length() > 0) {
                 clientUser.setAlias(sdkConfig.getChainClient().getAlias());
             }
        }

        clientUser.setAuthType(chainClientConfig.getAuthType());

        List<Node> nodeList = new ArrayList<>();

        for (NodeConfig nodeConfig : sdkConfig.getChainClient().getNodes()) {
            List<byte[]> tlsCaCertList = new ArrayList<>();
            if (nodeConfig.getTrustRootBytes() == null) {
                for (String rootPath : nodeConfig.getTrustRootPaths()) {
                    List<String> filePathList = FileUtils.getFilesByPath(rootPath);
                    for (String filePath : filePathList) {
                        tlsCaCertList.add(FileUtils.getFileBytes(filePath));
                    }
                }

                byte[][] tlsCaCerts = new byte[tlsCaCertList.size()][];
                tlsCaCertList.toArray(tlsCaCerts);
                nodeConfig.setTrustRootBytes(tlsCaCerts);
            }

            String url;

            if (nodeConfig.isEnableTls()) {
                url = "grpcs://" + nodeConfig.getNodeAddr();
            } else {
                url = "grpc://" + nodeConfig.getNodeAddr();
            }

            Node node = new Node();
            node.setTlsCertBytes(nodeConfig.getTrustRootBytes());
            node.setHostname(nodeConfig.getTlsHostName());
            node.setGrpcUrl(url);
            node.setSslProvider(OPENSSL_PROVIDER);
            node.setNegotiationType(TLS_NEGOTIATION);
            node.setConnectCount(nodeConfig.getConnCnt());
            nodeList.add(node);
        }

        Node[] nodes = new Node[nodeList.size()];
        nodeList.toArray(nodes);
        return createChainClient(chainId, clientUser, nodes, chainClientConfig.getRpcClient().getMaxReceiveMessageSize(),
                chainClientConfig.getRetryInterval(), chainClientConfig.getRetryLimit(), chainClientConfig.getArchive());
    }

    // create a chain client by chain id, client user and nodes
    private ChainClient createChainClient(String chainId, User clientUser, Node[] nodes, int messageSize, int retryInterval, int retryLimit,
            ArchiveConfig archiveConfig)
            throws RpcServiceClientException, UtilsException, ChainClientException {
        ChainClient chainClient = chains.get(chainId);
        if (chainClient != null) {
            return chainClient;
        }
        List<RpcServiceClient> rpcServiceClients = new ArrayList<>();
        for (Node node : nodes) {
            for (int i = 0; i < node.getConnectCount(); i++) {
                RpcServiceClient rpcServiceClient = RpcServiceClient.newServiceClient(node, clientUser, messageSize);
                rpcServiceClients.add(rpcServiceClient);
            }
        }

        // 打散洗牌，用作负载均衡
        Collections.shuffle(rpcServiceClients);

        ConnectionPool connectionPool = new ConnectionPool();
        connectionPool.setPrivateKey(clientUser.getTlsPrivateKey());
        connectionPool.setCertificate(clientUser.getTlsCertificate());
        connectionPool.setRpcServiceClients(rpcServiceClients);
        if (retryInterval != 0 && retryLimit != 0) {
            connectionPool.setRetryInterval(retryInterval);
            connectionPool.setRetryLimit(retryLimit);
        }

        chainClient = new ChainClient();
        chainClient.setChainId(chainId);
        chainClient.setClientUser(clientUser);
        chainClient.setConnectionPool(connectionPool);
        chainClient.setArchiveConfig(archiveConfig);

        chains.put(chainId, chainClient);

        if (chainClient.getClientUser().getAlias() != null && chainClient.getClientUser().getAlias().length() > 0) {
            try {
                chainClient.enableAlias();
            } catch (ChainMakerCryptoSuiteException | ChainClientException e) {
                throw new ChainClientException("enable Alias failed: " + e.getMessage());
            }
        }
        return chainClient;
    }

    private void dealChainClientConfig(ChainClientConfig chainClientConfig)
            throws UtilsException, ChainMakerCryptoSuiteException {

        String authType = chainClientConfig.getAuthType();
        if (authType.equals(AuthType.PermissionedWithKey.getMsg()) || authType.equals(AuthType.Public.getMsg())) {
            byte[] pemKey = FileUtils.getFileBytes(chainClientConfig.getUserSignKeyFilePath());

            KeyFactory kf;
            RSAPrivateKeySpec priv;
            PublicKey publicKey;
            try {
                kf = KeyFactory.getInstance("RSA");
                priv = kf.getKeySpec(CryptoUtils.getPrivateKeyFromBytes(pemKey), RSAPrivateKeySpec.class);
                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(priv.getModulus(), BigInteger.valueOf(65537));
                publicKey = kf.generatePublic(keySpec);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new ChainMakerCryptoSuiteException("new RSAPublicKeySpec err: " + e.getMessage());
            }
            chainClientConfig.setPublicKey(publicKey);
        } else {
            chainClientConfig.setAuthType(AuthType.PermissionedWithCert.getMsg());
            byte[] userKeyBytes = chainClientConfig.getUserKeyBytes();

            if (userKeyBytes == null && chainClientConfig.getUserKeyFilePath() != null) {
                chainClientConfig.setUserKeyBytes(FileUtils.getFileBytes(chainClientConfig.getUserKeyFilePath()));
            }

            byte[] userCrtBytes = chainClientConfig.getUserCrtBytes();
            if (userCrtBytes == null && chainClientConfig.getUserCrtFilePath() != null) {
                chainClientConfig.setUserCrtBytes(FileUtils.getFileBytes(chainClientConfig.getUserCrtFilePath()));
            }

            byte[] userSignKeyBytes = chainClientConfig.getUserSignKeyBytes();
            if (userSignKeyBytes == null && chainClientConfig.getUserSignKeyFilePath() != null) {
                chainClientConfig.setUserSignKeyBytes(FileUtils.getFileBytes(chainClientConfig.getUserSignKeyFilePath()));
            }

            byte[] userSignCrtBytes = chainClientConfig.getUserSignCrtBytes();
            if (userSignCrtBytes == null && chainClientConfig.getUserSignCrtFilePath() != null) {
                chainClientConfig.setUserSignCrtBytes(FileUtils.getFileBytes(chainClientConfig.getUserSignCrtFilePath()));
            }
        }

    }

    private void checkConfig(ChainClientConfig chainClientConfig) throws ChainClientException {
        if (chainClientConfig == null) {
            logger.error("chainClientConfig is null, please check config");
            throw new ChainClientException("chainClientConfig is null");
        }

        checkNodeListConfig(chainClientConfig);
        checkUserConfig(chainClientConfig);
        checkChainConfig(chainClientConfig);
    }

    private void checkNodeListConfig(ChainClientConfig chainClientConfig) throws ChainClientException {

        NodeConfig[] nodeConfigs = chainClientConfig.getNodes();

        for (NodeConfig nodeConfig : nodeConfigs) {
            if (nodeConfig.getConnCnt() <= 0 || nodeConfig.getConnCnt() > NodeConfig.maxConnCnt) {
                throw new ChainClientException(String.format("node connection count should >0 && <=%d", NodeConfig.maxConnCnt));
            }

            if (nodeConfig.isEnableTls()) {
                if (nodeConfig.getTrustRootBytes() == null && nodeConfig.getTrustRootPaths() == null) {
                    throw new ChainClientException("if node useTLS is open, should set caPaths or caCerts");
                }
            }

            if ("".equals(nodeConfig.getTlsHostName())) {
                throw new ChainClientException("if node useTLS is open, should set tls hostname");
            }
        }
    }

    private void checkUserConfig(ChainClientConfig chainClientConfig) throws ChainClientException {
        if ("".equals(chainClientConfig.getUserKeyFilePath()) && chainClientConfig.getUserKeyBytes() == null) {
            throw new ChainClientException("user key cannot be empty");
        }
        if ("".equals(chainClientConfig.getUserCrtFilePath()) && chainClientConfig.getUserCrtBytes() == null) {
            throw new ChainClientException("user cert cannot be empty");
        }
    }

    private void checkChainConfig(ChainClientConfig chainClientConfig) throws ChainClientException {
        if ("".equals(chainClientConfig.getChainId())) {
            throw new ChainClientException("chainId cannot be empty");
        }
    }
}
