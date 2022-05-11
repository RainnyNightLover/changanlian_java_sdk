/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.crypto.hibe;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.List;

import org.chainmaker.sdk.SdkException;
import org.chainmaker.sdk.crypto.ChainMakerCryptoSuiteException;
import org.chainmaker.sdk.crypto.hibe.gotype.GoBytes.ByValue;
import org.chainmaker.sdk.crypto.hibe.gotype.GoString;
import org.chainmaker.sdk.serialize.EasyCodecHelper;

import com.sun.jna.Native;
import com.sun.jna.Pointer;

public class Hibe {

    static final String SIZE = "size";

    public byte[] encryptHibeMsg(byte[] plainText, String[] receiverIds, List<byte[]> params, int keyType) throws SdkException {
        ByValue encryptHibeMsg = null;
        try {
            EasyCodecHelper helper1 = new EasyCodecHelper();
            helper1.addInt(SIZE, receiverIds.length);
            for (int i = 0; i < receiverIds.length; i++) {
                helper1.addString(String.valueOf(i), receiverIds[i]);

            }
            byte[] idsBytes = helper1.EasyMarshal();

            EasyCodecHelper helper2 = new EasyCodecHelper();
            helper2.addInt(SIZE, 1);
            for (int i = 0; i < params.size(); i++) {
                helper2.addBytes(String.valueOf(i), params.get(i));
            }
            byte[] paramsBytes = helper2.EasyMarshal();
            encryptHibeMsg = HibeBase.getHibeInterface().EncryptHibeMsg(plainText,
                    plainText.length, idsBytes, idsBytes.length, paramsBytes, paramsBytes.length, keyType);

            if (encryptHibeMsg.r1 != -1) {
                return encryptHibeMsg.r0.getByteArray(0, (int) encryptHibeMsg.r1);
            }
            return null;
        } catch (SdkException | IOException e) {
            throw new SdkException("EncryptHibeMsg err : " + e.getMessage());
        } finally {
            String os = System.getProperty("os.name");
            if (!os.toLowerCase().startsWith("win")) {
                if (encryptHibeMsg != null && encryptHibeMsg.r0 != null) {
                    Native.free(Pointer.nativeValue(encryptHibeMsg.r0));
                }
            }
        }
    }

    public byte[] decryptHibeMsg(String localId, byte[] param, byte[] privKey, byte[] hibeMsg, int keyType) throws SdkException {
        byte[] localIdBytes = localId.getBytes();
        ByValue decryptMsg = null;
        try {
            try {
                decryptMsg = HibeBase.getHibeInterface().DecryptHibeMsg(localIdBytes, localIdBytes.length, param, param.length, privKey, privKey.length, hibeMsg, hibeMsg.length, keyType);
            } catch (SdkException e) {
                throw new SdkException("DecryptHibeMsg err : " + e.getMessage());
            }
            if (decryptMsg.r1 != -1) {
                return decryptMsg.r0.getByteArray(0, (int) decryptMsg.r1);
            }
            return null;
        } finally {
            if (decryptMsg != null && decryptMsg.getPointer() != null) {
                String os = System.getProperty("os.name");
                if (!os.toLowerCase().startsWith("win")) {
                    if (decryptMsg.r0 != null) {
                        Native.free(Pointer.nativeValue(decryptMsg.r0));
                    }
                }

            }
        }
    }

    public byte[] readKey(String file) throws UnsupportedEncodingException, ChainMakerCryptoSuiteException {
        ByValue curve = null;
        try {
            curve = HibeBase.getHibeInterface().ReadKey(new GoString.ByValue(file));

            if (curve.r1 != -1) {
                return curve.r0.getByteArray(0, (int) curve.r1);
            }
            return null;
        } finally {
            String os = System.getProperty("os.name");
            if (!os.toLowerCase().startsWith("win")) {
                if (curve != null && curve.getPointer() != null) {
                    Native.free(Pointer.nativeValue(curve.r0));
                }
            }
        }
    }

    public static void printHex(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(bytes[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
                System.out.print(hex);
            }
        }
        System.out.println();
    }

}
