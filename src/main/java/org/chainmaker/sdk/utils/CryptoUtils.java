/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.utils;

import java.io.StringWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.jcajce.provider.digest.Keccak;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.chainmaker.sdk.crypto.ChainMakerCryptoSuiteException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import org.web3j.crypto.Hash;

public class CryptoUtils {

    private static final int ZX_ADDR_SUFFIX_LENGTH = 20;
    private static final String ZX_ADDR_PREFIX = "ZX";
    private static final String RSA_PRE = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A";
    private static final String HEX_ADDR_PREFIX = "0x";

    private CryptoUtils() {
        throw new IllegalStateException("Crypto Utils class");
    }

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static PrivateKey getPrivateKeyFromBytes(byte[] pemKey) throws ChainMakerCryptoSuiteException {
        PrivateKey pk = null;

        try {
            PemReader pr = new PemReader(new StringReader(new String(pemKey)));
            PemObject po = pr.readPemObject();
            PEMParser pem = new PEMParser(new StringReader(new String(pemKey)));

            if (po.getType().equals("PRIVATE KEY")) {
                pk = new JcaPEMKeyConverter().getPrivateKey((PrivateKeyInfo) pem.readObject());
            } else {
                PEMKeyPair kp = (PEMKeyPair) pem.readObject();
                pk = new JcaPEMKeyConverter().getPrivateKey(kp.getPrivateKeyInfo());
            }
        } catch (Exception e) {
            throw new ChainMakerCryptoSuiteException(e.toString());
        }
        return pk;
    }

    public static String makeAddrFromPukPem(PublicKey publicKey) throws IOException {
        byte[] encoded = publicKey.getEncoded();
        SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(
                ASN1Sequence.getInstance(encoded));
        byte[] subjectPublicKeyEncoded = subjectPublicKeyInfo.parsePublicKey().getEncoded();

        Digest digest = new  SHA256Digest();
        byte[] retValue = new byte[digest.getDigestSize()];
        digest.update(subjectPublicKeyEncoded, 0, subjectPublicKeyEncoded.length);
        digest.doFinal(retValue, 0);

        String ski = Hex.toHexString(retValue);

        byte[] data = Hex.decode(ski);
        Keccak.DigestKeccak kecc = new Keccak.Digest256();
        kecc.update(data, 0, data.length);
        byte[] address = kecc.digest();
        String addr = Hex.toHexString(address);
        return HEX_ADDR_PREFIX + addr.substring(24);
    }

    public static String makeAddrFromCert(Certificate certificate) throws UtilsException {

        ByteArrayInputStream bIn = null;
        try {
            bIn = new ByteArrayInputStream(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new UtilsException("certificate to ByteArrayInputStream err : " + e.getMessage());
        }
        ASN1InputStream aIn = new ASN1InputStream(bIn);

        ASN1Sequence seq = null;
        try {
            seq = (ASN1Sequence)aIn.readObject();
        } catch (IOException e) {
            throw new UtilsException("certificate to ASN1Sequence err : " + e.getMessage());
        }

        org.bouncycastle.asn1.x509.Certificate obj = org.bouncycastle.asn1.x509.Certificate.getInstance(seq);
        TBSCertificate tbsCertificate = obj.getTBSCertificate();
        Extensions ext = tbsCertificate.getExtensions();

        SubjectKeyIdentifier si = SubjectKeyIdentifier.fromExtensions(ext);
        String ski = Hex.toHexString(si.getKeyIdentifier());

        byte[] data = Hex.decode(ski);
        Keccak.DigestKeccak kecc = new Keccak.Digest256();
        kecc.update(data, 0, data.length);
        byte[] address = kecc.digest();
        String addr = Hex.toHexString(address);
        return HEX_ADDR_PREFIX + addr.substring(24);
    }

    public static String getPemStrFromPublicKey(PublicKey publicKey) throws UtilsException  {
        StringWriter writer = new StringWriter();
        PemWriter pemWriter = new PemWriter(writer);
        try {
            pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
            pemWriter.flush();
            pemWriter.close();
        } catch (IOException e) {
            throw new UtilsException("publicKey parse to pem err :" + e.getMessage());
        }

        return writer.toString();
    }

    public static String getZXAddressFromPKPEM(String pk) throws UtilsException {
        pk = pk.replace(RSA_PRE, "");
        PemReader pr = new PemReader(new StringReader(new String(pk)));
        PemObject po = null;
        byte[] plainText = null;
        try {
            po = pr.readPemObject();
            RSAPublicKey rsaPublicKey = RSAPublicKey.getInstance(po.getContent());
            plainText = rsaPublicKey.toASN1Primitive().getEncoded();
        } catch (IOException e) {
            throw new UtilsException("publicKey parse to addr err :" + e.getMessage());
        }
        Digest digest = new SM3Digest();
        byte[] retValue = new byte[digest.getDigestSize()];
        digest.update(plainText, 0, plainText.length);
        digest.doFinal(retValue, 0);
        byte[] addrBytes = new byte[ZX_ADDR_SUFFIX_LENGTH];
        System.arraycopy(retValue, 0, addrBytes, 0, ZX_ADDR_SUFFIX_LENGTH);
        return ZX_ADDR_PREFIX + Hex.toHexString(addrBytes);
    }

}
