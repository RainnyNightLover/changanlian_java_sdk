/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.utils;

import com.google.protobuf.ByteString;
import io.netty.util.internal.StringUtil;
import org.bouncycastle.util.encoders.Hex;
import org.chainmaker.sdk.crypto.ChainMakerCryptoSuiteException;
import org.chainmaker.sdk.crypto.ChainmakerX509CryptoSuite;
import org.chainmaker.sdk.crypto.CryptoSuite;

import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.web3j.crypto.Hash;

import static java.lang.String.format;

public class Utils {
    private Utils() {
        throw new IllegalStateException("Utils class");
    }

    public static long getCurrentTimeSeconds() {
        return System.currentTimeMillis() / 1000;
    }

    public static String generateTxId(ByteString seed, CryptoSuite cryptoSuite) throws ChainMakerCryptoSuiteException {
        return Hex.toHexString(cryptoSuite.hash(seed.toByteArray()));
    }

    public static Properties parseGrpcUrl(String grpcUrl) throws UtilsException {
        if (StringUtil.isNullOrEmpty(grpcUrl)) {
            throw new UtilsException("URL cannot be null or empty");
        }

        Properties props = new Properties();
        Pattern p = Pattern.compile("([^:]+)[:]//([^ ]+)[:]([0-9]+)", Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(grpcUrl);
        if (m.matches()) {
            props.setProperty("protocol", m.group(1));
            props.setProperty("host", m.group(2));
            props.setProperty("port", m.group(3));

            String protocol = props.getProperty("protocol");
            if (!"grpc".equals(protocol) && !"grpcs".equals(protocol)) {
                throw new UtilsException(format("Invalid protocol expected grpc or grpcs and found %s.", protocol));
            }
        } else {
            throw new UtilsException("URL must be of the format protocol://host:port. Found: '" + grpcUrl + "'");
        }

        return props;
    }

    public static String joinList(String[] strList) {
        StringBuilder result = new StringBuilder();

        for (String str : strList) {
            result.append(str).append(",");
        }
        result.deleteCharAt(result.length() - 1);
        return result.toString();
    }

    public static byte[] longToByteLittleEndian(long l) {
        byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            int i1 = i << 3;
            bytes[i] = (byte) ((l >> i1) & 0xff);
        }
        return bytes;
    }

    public static String calcContractName(String contractName) {
        return Hash.sha3String(contractName).substring(26);
    }
}
