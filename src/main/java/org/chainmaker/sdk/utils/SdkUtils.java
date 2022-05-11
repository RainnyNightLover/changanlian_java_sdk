/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.utils;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.chainmaker.pb.accesscontrol.MemberOuterClass;
import org.chainmaker.pb.accesscontrol.MemberOuterClass.MemberType;
import org.chainmaker.pb.common.Request;
import org.chainmaker.sdk.User;
import org.chainmaker.sdk.config.AuthType;
import org.chainmaker.sdk.crypto.ChainMakerCryptoSuiteException;

public class SdkUtils {
    public static Request.EndorsementEntry[] getEndorsers(Request.Payload payload, User[] users)
            throws ChainMakerCryptoSuiteException, UtilsException {

        Request.EndorsementEntry[] endorsementEntries = new Request.EndorsementEntry[users.length];

        for (int i = 0; i < users.length; i++) {
            Request.EndorsementEntry entry = signPayload(users[i], payload.toByteArray());
            endorsementEntries[i] = entry;
        }
        return endorsementEntries;
    }

    private static Request.EndorsementEntry signPayload(User user, byte[] payload)
            throws ChainMakerCryptoSuiteException, UtilsException {
        if (user.getAuthType().equals(AuthType.PermissionedWithCert.getMsg())) {
            return Request.EndorsementEntry.newBuilder().setSignature(
                    ByteString.copyFrom(user.getCryptoSuite().sign(user.getPrivateKey(), payload)))
                    .setSigner(getSerializedMember(user)).build();
        } else {
            return Request.EndorsementEntry.newBuilder().setSignature(
                    ByteString.copyFrom(user.getCryptoSuite().rsaSign(CryptoUtils.getPrivateKeyFromBytes(user.getPriBytes()), payload)))
                    .setSigner(getSerializedMember(user.getOrgId(), user.getPriBytes())).build();
        }
    }

    // Get the SerializedMember according whether enabled cert hash
    public static MemberOuterClass.Member getSerializedMember(User user) {
        return MemberOuterClass.Member.newBuilder()
                .setOrgId(user.getOrgId())
                .setMemberInfo(ByteString.copyFrom(user.getCertBytes()))
                .setMemberType(MemberOuterClass.MemberType.CERT)
                .build();
    }

    public static MemberOuterClass.Member getSerializedMember(String orgId, byte[] pkBytes) throws UtilsException {
        return MemberOuterClass.Member.newBuilder()
                .setOrgId(orgId)
                .setMemberInfo(ByteString.copyFrom(dealRsaPk(pkBytes)))
                .setMemberType(MemberOuterClass.MemberType.PUBLIC_KEY)
                .build();
    }

    public static byte[] dealRsaPk(byte[] pemKey) throws UtilsException {
        KeyFactory kf;
        RSAPrivateKeySpec priv;
        PublicKey publicKey;
        try {
            kf = KeyFactory.getInstance("RSA");
            priv = kf.getKeySpec(CryptoUtils.getPrivateKeyFromBytes(pemKey), RSAPrivateKeySpec.class);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(priv.getModulus(), BigInteger.valueOf(65537));
            publicKey = kf.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | ChainMakerCryptoSuiteException e) {
            throw new UtilsException("new RSAPublicKeySpec err: " + e.getMessage());
        }

        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);
        try {
            pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
            pemWriter.flush();
            pemWriter.close();
        } catch (IOException e) {
            throw new UtilsException("publicKey parse to pem err :" + e.getMessage());
        }

        return writer.toString().getBytes();
    }

}

