/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk;

import com.google.protobuf.ByteString;
import java.security.PublicKey;
import org.chainmaker.pb.accesscontrol.MemberOuterClass.Member;
import org.chainmaker.pb.accesscontrol.MemberOuterClass;
import org.chainmaker.pb.common.Request;
import org.chainmaker.sdk.config.AuthType;
import org.chainmaker.sdk.crypto.ChainMakerCryptoSuiteException;
import org.chainmaker.sdk.crypto.ChainmakerX509CryptoSuite;
import org.chainmaker.sdk.crypto.CryptoSuite;
import org.chainmaker.sdk.utils.CryptoUtils;

import java.security.PrivateKey;
import java.security.cert.Certificate;

/*
 User means a people who use the chains. Usually a user has a private key, a cert and an organization,
 so you can use a user to sign a transaction.
 */
public class User {

    // the organization id of the user
    private String orgId;
    // user's private key used to sign transaction
    private PrivateKey privateKey;
    // user's certificate
    private Certificate certificate;
    // user's private key used to sign transaction
    private PrivateKey tlsPrivateKey;
    // user's certificate
    private Certificate tlsCertificate;
    // the bytes of user's certificate
    private byte[] certBytes;
    // the hash of the cert
    private byte[] certHash;
    // the alias of the cert
    private String alias;
    // no bytes of pk
    private byte[] pukBytes;

    private byte[] priBytes;

    private PublicKey publicKey;

    private String authType = AuthType.PermissionedWithCert.getMsg();

    private CryptoSuite cryptoSuite;

    // Construct a user by organization id, user's private key bytes and user's cert bytes
    public User(String orgId, byte[] userKeyBytes, byte[] userCertBytes, byte[] tlsUserKeyBytes,
            byte[] tlsUserCertBytes)
            throws ChainMakerCryptoSuiteException {
        PrivateKey generatedPrivateKey = CryptoUtils.getPrivateKeyFromBytes(userKeyBytes);
        PrivateKey generatedTlsPrivateKey = CryptoUtils.getPrivateKeyFromBytes(tlsUserKeyBytes);
        CryptoSuite generatedCryptoSuite = ChainmakerX509CryptoSuite.newInstance();
        Certificate generatedCertificate = generatedCryptoSuite.getCertificateFromBytes(userCertBytes);
        Certificate generatedTlsCertificate = generatedCryptoSuite.getCertificateFromBytes(tlsUserCertBytes);
        this.orgId = orgId;
        this.certBytes = userCertBytes;
        this.privateKey = generatedPrivateKey;
        this.tlsCertificate = generatedTlsCertificate;
        this.tlsPrivateKey = generatedTlsPrivateKey;
        this.cryptoSuite = generatedCryptoSuite;
        this.certificate = generatedCertificate;
    }

    public User(String orgId) throws ChainMakerCryptoSuiteException {
        this.cryptoSuite = ChainmakerX509CryptoSuite.newInstance();
        this.orgId = orgId;
    }

    public String getOrgId() {
        return orgId;
    }

    public void setOrgId(String orgId) {
        this.orgId = orgId;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public PrivateKey getTlsPrivateKey() {
        return tlsPrivateKey;
    }

    public void setTlsPrivateKey(PrivateKey tlsPrivateKey) {
        this.tlsPrivateKey = tlsPrivateKey;
    }

    public Certificate getTlsCertificate() {
        return tlsCertificate;
    }

    public void setTlsCertificate(Certificate tlsCertificate) {
        this.tlsCertificate = tlsCertificate;
    }

    public byte[] getCertBytes() {
        return certBytes;
    }

    public void setCertBytes(byte[] certBytes) {
        this.certBytes = certBytes;
    }

    public byte[] getCertHash() {
        return certHash;
    }

    public void setCertHash(byte[] certHash) {
        this.certHash = certHash;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public byte[] getPukBytes() {
        return pukBytes;
    }

    public void setPukBytes(byte[] pukBytes) {
        this.pukBytes = pukBytes;
    }

    public byte[] getPriBytes() {
        return priBytes;
    }

    public void setPriBytes(byte[] priBytes) {
        this.priBytes = priBytes;
    }

    public String getAuthType() {
        return authType;
    }

    public void setAuthType(String authType) {
        this.authType = authType;
    }

    public CryptoSuite getCryptoSuite() {
        return cryptoSuite;
    }

    public void setCryptoSuite(CryptoSuite cryptoSuite) {
        this.cryptoSuite = cryptoSuite;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    // Sign the payload of contract management
    public byte[] signPayload(byte[] payload, boolean isEnabledCertHash)
            throws ChainMakerCryptoSuiteException {

        Request.EndorsementEntry endorsementEntry = Request.EndorsementEntry.newBuilder().setSignature(
                ByteString.copyFrom(cryptoSuite.sign(privateKey, payload)))
                .setSigner(getSerializedMember(isEnabledCertHash)).build();
        return endorsementEntry.toByteArray();
    }

    // Sign the payload of multi sign request and return the endorsement
    public Request.EndorsementEntry signPayloadOfMultiSign(byte[] payload, boolean isEnabledCertHash)
            throws ChainMakerCryptoSuiteException {
        return Request.EndorsementEntry.newBuilder().setSignature(
                ByteString.copyFrom(cryptoSuite.sign(privateKey, payload)))
                .setSigner(getSerializedMember(isEnabledCertHash)).build();
    }

    // Get the SerializedMember according whether enabled cert hash
    public Member getSerializedMember(boolean isEnabledCertHash) {
        if (isEnabledCertHash && certHash != null && certHash.length > 0) {
            return Member.newBuilder()
                    .setOrgId(orgId)
                    .setMemberInfo(ByteString.copyFrom(certHash))
                    .setMemberType(MemberOuterClass.MemberType.CERT_HASH)
                    .build();
        }
        return Member.newBuilder()
                .setOrgId(orgId)
                .setMemberInfo(ByteString.copyFrom(certBytes))
                .setMemberType(MemberOuterClass.MemberType.CERT)
                .build();
    }
}
