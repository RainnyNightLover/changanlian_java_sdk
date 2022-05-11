/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk;

import org.chainmaker.sdk.config.*;
import org.chainmaker.sdk.utils.FileUtils;
import org.junit.Before;
import org.junit.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

public class TestBaseA {

    static String ORG1_CERT_PATH = "crypto-config/wx-org1.chainmaker.org/ca/ca.crt";
    static String CLIENT1_TLS_KEY_PATH = "crypto-config/wx-org1.chainmaker.org/user/client1/client1.tls.key";
    static String CLIENT1_TLS_CERT_PATH = "crypto-config/wx-org1.chainmaker.org/user/client1/client1.tls.crt";
    static String CLIENT1_KEY_PATH = "crypto-config/wx-org1.chainmaker.org/user/client1/client1.sign.key";
    static String CLIENT1_CERT_PATH = "crypto-config/wx-org1.chainmaker.org/user/client1/client1.sign.crt";
    static String TLS_HOST_NAME1 = "chainmaker.org";
    static int CONNECT_COUNT = 10;

    static String ADMIN1_TLS_KEY_PATH = "crypto-config/wx-org1.chainmaker.org/user/admin1/admin1.tls.key";
    static String ADMIN1_TLS_CERT_PATH = "crypto-config/wx-org1.chainmaker.org/user/admin1/admin1.tls.crt";
    static String ADMIN2_TLS_KEY_PATH = "crypto-config/wx-org2.chainmaker.org/user/admin1/admin1.tls.key";
    static String ADMIN2_TLS_CERT_PATH = "crypto-config/wx-org2.chainmaker.org/user/admin1/admin1.tls.crt";
    static String ADMIN3_TLS_KEY_PATH = "crypto-config/wx-org3.chainmaker.org/user/admin1/admin1.tls.key";
    static String ADMIN3_TLS_CERT_PATH = "crypto-config/wx-org3.chainmaker.org/user/admin1/admin1.tls.crt";

    static String ADMIN1_KEY_PATH = "crypto-config/wx-org1.chainmaker.org/user/admin1/admin1.sign.key";
    static String ADMIN1_CERT_PATH = "crypto-config/wx-org1.chainmaker.org/user/admin1/admin1.sign.crt";
    static String ADMIN2_KEY_PATH = "crypto-config/wx-org2.chainmaker.org/user/admin1/admin1.sign.key";
    static String ADMIN2_CERT_PATH = "crypto-config/wx-org2.chainmaker.org/user/admin1/admin1.sign.crt";
    static String ADMIN3_KEY_PATH = "crypto-config/wx-org3.chainmaker.org/user/admin1/admin1.sign.key";
    static String ADMIN3_CERT_PATH = "crypto-config/wx-org3.chainmaker.org/user/admin1/admin1.sign.crt";

    static String ADMIN1_PK_PATH = "crypto-config/node1/admin/admin1/admin1.key";
    static String ADMIN2_PK_PATH = "crypto-config/node1/admin/admin2/admin2.key";
    static String ADMIN3_PK_PATH = "crypto-config/node1/admin/admin3/admin3.key";

    private static final String CHAIN_ID = "chain1";
    private static final int MAX_MESSAGE_SIZE = 16;

    static String CLIENT_CRL_PATH = "crl/client1.crl";

    static String ORG_ID1 = "wx-org1.chainmaker.org";
    static String ORG_ID2 = "wx-org2.chainmaker.org";
    static String ORG_ID3 = "wx-org3.chainmaker.org";

    static String NODE_GRPC_URL1 = "127.0.0.1:12301";

    static String TYPE = "mysql";
    static String DEST = "root:123456:localhost:3306";
    static String SECRET_KEY = "xxx";
    static String SDK_CONFIG = "sdk_config.yml";

    ChainClient chainClient;
    ChainManager chainManager;
    User adminUser1;
    User adminUser2;
    User adminUser3;

    long rpcCallTimeout = 10000;
    long syncResultTimeout = 10000;

    @Before
    public void init() throws IOException, SdkException {

        //通过sdk_config.yaml配置文件创建
        //如果不想通过配置文件设置参数，可自定义SdkConfig对象，设置SdkConfig中各个属性，参考initWithNoConfig
        Yaml yaml = new Yaml();
        InputStream in = TestBaseA.class.getClassLoader().getResourceAsStream(SDK_CONFIG);

        SdkConfig sdkConfig;
        sdkConfig = yaml.loadAs(in, SdkConfig.class);
        assert in != null;
        in.close();

        for (NodeConfig nodeConfig : sdkConfig.getChainClient().getNodes()) {
            List<byte[]> tlsCaCertList = new ArrayList<>();
            if (nodeConfig.getTrustRootPaths() != null) {
                for (String rootPath : nodeConfig.getTrustRootPaths()) {
                    List<String> filePathList = FileUtils.getFilesByPath(rootPath);
                    for (String filePath : filePathList) {
                        tlsCaCertList.add(FileUtils.getFileBytes(filePath));
                    }
                }
            }
            byte[][] tlsCaCerts = new byte[tlsCaCertList.size()][];
            tlsCaCertList.toArray(tlsCaCerts);
            nodeConfig.setTrustRootBytes(tlsCaCerts);
        }

        chainManager = ChainManager.getInstance();
        chainClient = chainManager.getChainClient(sdkConfig.getChainClient().getChainId());

        if (chainClient == null) {
            chainClient = chainManager.createChainClient(sdkConfig);
            System.out.println("hello");
            System.out.println(chainClient);
        }
        System.out.println("hello");

        //公钥模式下，多签用户
//        adminUser1 = new User(ORG_ID1);
//        adminUser1.setAuthType(AuthType.Public.getMsg());
//        adminUser1.setPriBytes(FileUtils.getResourceFileBytes(ADMIN1_PK_PATH));
//
//        adminUser2 = new User(ORG_ID2);
//        adminUser2.setAuthType(AuthType.Public.getMsg());
//        adminUser2.setPriBytes(FileUtils.getResourceFileBytes(ADMIN2_PK_PATH));
//
//        adminUser3 = new User(ORG_ID3);
//        adminUser3.setAuthType(AuthType.Public.getMsg());
//        adminUser3.setPriBytes(FileUtils.getResourceFileBytes(ADMIN3_PK_PATH));

      /*  adminUser1 = new User(ORG_ID1, FileUtils.getResourceFileBytes(ADMIN1_KEY_PATH),
                FileUtils.getResourceFileBytes(ADMIN1_CERT_PATH),
                FileUtils.getResourceFileBytes(ADMIN1_TLS_KEY_PATH),
                FileUtils.getResourceFileBytes(ADMIN1_TLS_CERT_PATH));

        adminUser2 = new User(ORG_ID2, FileUtils.getResourceFileBytes(ADMIN2_KEY_PATH),
                FileUtils.getResourceFileBytes(ADMIN2_CERT_PATH),
                FileUtils.getResourceFileBytes(ADMIN2_TLS_KEY_PATH),
                FileUtils.getResourceFileBytes(ADMIN2_TLS_CERT_PATH));

        adminUser3 = new User(ORG_ID3, FileUtils.getResourceFileBytes(ADMIN3_KEY_PATH),
                FileUtils.getResourceFileBytes(ADMIN3_CERT_PATH),
                FileUtils.getResourceFileBytes(ADMIN3_TLS_KEY_PATH),
                FileUtils.getResourceFileBytes(ADMIN3_TLS_CERT_PATH));*/
    }

    @Test
    public void run(){
        System.out.println("test");
    }
}

