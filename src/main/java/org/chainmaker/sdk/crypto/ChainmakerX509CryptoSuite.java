/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.crypto;

import org.apache.commons.collections.CollectionUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
//如果jdk中引用的sun.security.ec.CurveDB不存在，则需引用sun.security.util.CurveDB
import sun.security.ec.CurveDB;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

// ChainmakerX509CryptoSuite is a security library suite used to sign payload, store ca trust roots, etc.
public class ChainmakerX509CryptoSuite implements CryptoSuite {
    private static final String HASH_ALGORITHM = "SHA256";
    private static final String CERTIFICATE_FORMAT = "X.509";
    private static final String ALGORITHM_SM2_KEY = "SM3withSM2";
    private static final String ALGORITHM_RSA = "SHA256withRSA";
    private static String algorithm;

    private static final Logger logger = LoggerFactory.getLogger(ChainmakerX509CryptoSuite.class);

    static {
        try {
            enableX509CertificateWithGM();
        } catch (Exception e) {
            logger.error("CurveDB enableGM err : ", e);
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final List<String> HASH_TYPE_SET = Arrays.asList(HASH_ALGORITHM, "SM3", "SHA3");

    private static final String curveName = "secp384r1";

    private KeyStore trustStore = null;

    // new crypto suite instance
    public static ChainmakerX509CryptoSuite newInstance() throws ChainMakerCryptoSuiteException {
        return new ChainmakerX509CryptoSuite();
    }

    private ChainmakerX509CryptoSuite() throws ChainMakerCryptoSuiteException {
        createTrustStore();
    }

    // load ca certificates
    @Override
    public void loadCACertificates(Collection<Certificate> certificates) throws ChainMakerCryptoSuiteException {
        if (CollectionUtils.isEmpty(certificates)) {
            throw new ChainMakerCryptoSuiteException("Unable to load CA certificates. List is empty");
        }

        try {
            for (Certificate cert : certificates) {
                addCACertificateToTrustStore(cert);
            }
        } catch (Exception e) {
            // Note: This can currently never happen (as cert<>null and alias<>null)
            throw new ChainMakerCryptoSuiteException(e.toString());
        }
    }

    // load ca certificates from certificate bytes
    @Override
    public void loadCACertificatesAsBytes(Collection<byte[]> certificates) throws ChainMakerCryptoSuiteException {
        if (CollectionUtils.isEmpty(certificates)) {
            throw new ChainMakerCryptoSuiteException("List of CA certificates is empty. Nothing to load.");
        }

        ArrayList<Certificate> certList = new ArrayList<>();
        for (byte[] certBytes : certificates) {
            certList.add(getCertificateFromBytes(certBytes));
        }
        loadCACertificates(certList);
    }

    private void addCACertificateToTrustStore(Certificate certificate) throws ChainMakerCryptoSuiteException {
        String alias;
        if (certificate instanceof X509Certificate) {
            alias = ((X509Certificate) certificate).getSerialNumber().toString();
        } else { // not likely ...
            alias = Integer.toString(certificate.hashCode());
        }
        addCACertificateToTrustStore(certificate, alias);
    }

    private void addCACertificateToTrustStore(Certificate caCert, String alias) throws ChainMakerCryptoSuiteException {

        if (alias == null || alias.isEmpty()) {
            throw new ChainMakerCryptoSuiteException("You must assign an alias to a certificate when adding to the trust store.");
        }

        if (caCert == null) {
            throw new ChainMakerCryptoSuiteException("Certificate cannot be null.");
        }

        try {
            if (trustStore.containsAlias(alias)) {
                return;
            }

            trustStore.setCertificateEntry(alias, caCert);

        } catch (KeyStoreException e) {
            throw new ChainMakerCryptoSuiteException(e.toString());
        }
    }

    private void createTrustStore() throws ChainMakerCryptoSuiteException {
        try {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            this.trustStore = keyStore;
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            throw new ChainMakerCryptoSuiteException(e.toString());
        }
    }

    // generate key pair
    @Override
    public KeyPair keyGen() throws ChainMakerCryptoSuiteException {
        return ecdsaKeyGen();
    }

    private KeyPair ecdsaKeyGen() throws ChainMakerCryptoSuiteException {
        return generateKey("EC", curveName);
    }

    private KeyPair generateKey(String encryptionName, String curveName) throws ChainMakerCryptoSuiteException {
        try {
            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(curveName);
            KeyPairGenerator g = KeyPairGenerator.getInstance(encryptionName);
            g.initialize(ecGenSpec, new SecureRandom());
            return g.generateKeyPair();
        } catch (Exception exp) {
            throw new ChainMakerCryptoSuiteException(exp.toString());
        }
    }

    // sign payload using private key
    @Override
    public byte[] sign(PrivateKey privateKey, byte[] plainText) throws ChainMakerCryptoSuiteException {
        if (plainText == null || plainText.length == 0) {
            throw new ChainMakerCryptoSuiteException("Data that to be signed is null.");
        }
        try {
            Signature sig = Signature.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            sig.initSign(privateKey);
            sig.update(plainText);
            return sig.sign();

        } catch (Exception e) {
            throw new ChainMakerCryptoSuiteException(e.toString());
        }
    }

    @Override
    public byte[] rsaSign(PrivateKey privateKey, byte[] plainText) throws ChainMakerCryptoSuiteException {
        if (plainText == null || plainText.length == 0) {
            throw new ChainMakerCryptoSuiteException("Data that to be signed is null.");
        }
        //NONEwithRSA
        try {
            Signature sig = Signature.getInstance(ALGORITHM_RSA, BouncyCastleProvider.PROVIDER_NAME);
            sig.initSign(privateKey);
            sig.update(plainText);
            return sig.sign();
        } catch (Exception e) {
            throw new ChainMakerCryptoSuiteException(e.toString());
        }
    }

    // verify the signature according certificate
    @Override
    public boolean verify(Certificate certificate, byte[] signature, byte[] plainText) throws ChainMakerCryptoSuiteException {
        boolean isVerified = false;

        try {
            Signature sig = Signature.getInstance(algorithm);
            sig.initVerify(certificate);
            sig.update(plainText);
            isVerified = sig.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            logger.error("verify fail : ", e);
            throw new ChainMakerCryptoSuiteException("verify fail fail : " + e.getMessage());
        }

        return isVerified;
    }

    // hash bytes and return the hash value
    @Override
    public byte[] hash(byte[] plainText) throws ChainMakerCryptoSuiteException {
        Digest digest = getHashDigest();
        byte[] retValue = new byte[digest.getDigestSize()];
        digest.update(plainText, 0, plainText.length);
        digest.doFinal(retValue, 0);
        return retValue;
    }

    private Digest getHashDigest() throws ChainMakerCryptoSuiteException {

        if (!HASH_TYPE_SET.contains(HASH_ALGORITHM.toUpperCase())) {
            throw new ChainMakerCryptoSuiteException("hash algorithm not support");
        }
        return new SHA256Digest();
    }

    // Get certificate from bytes
    @Override
    public Certificate getCertificateFromBytes(byte[] certBytes) throws ChainMakerCryptoSuiteException {
        if (certBytes == null || certBytes.length == 0) {
            throw new ChainMakerCryptoSuiteException("bytesToCertificate: input null or zero length");
        }
        return getX509Certificate(certBytes);
    }

    private static X509Certificate getX509Certificate(byte[] pemCertificate) throws ChainMakerCryptoSuiteException {
        X509Certificate ret = null;

        try {
            CertificateFactory cf = CertificateFactory.getInstance(CERTIFICATE_FORMAT, BouncyCastleProvider.PROVIDER_NAME);
            ByteArrayInputStream certInputStream = new ByteArrayInputStream(pemCertificate);
            ret = (X509Certificate) cf.generateCertificate(certInputStream);
        } catch (CertificateException | NoSuchProviderException e) {
            logger.error("convert pem bytes fail : ", e);
            throw new ChainMakerCryptoSuiteException("convert pem bytes fail : " + e.getMessage());
        }
        if (ret == null) {
            throw new ChainMakerCryptoSuiteException("can't convert pem bytes");
        }
        algorithm = ret.getSigAlgName();
        return ret;
    }

    private static ECPublicKeyParameters convertPublicKeyToParameters(BCECPublicKey ecPubKey) {
        ECParameterSpec parameterSpec = ecPubKey.getParameters();
        ECDomainParameters domainParameters = new ECDomainParameters(parameterSpec.getCurve(), parameterSpec.getG(),
                parameterSpec.getN(), parameterSpec.getH());
        return new ECPublicKeyParameters(ecPubKey.getQ(), domainParameters);
    }

    private static void enableX509CertificateWithGM() throws IllegalAccessException, InvocationTargetException,
            NoSuchFieldException, ClassNotFoundException, IOException {
        Method[] methods = CurveDB.class.getDeclaredMethods();
        Method method = null;

        Pattern splitPattern = Pattern.compile(",|\\[|\\]");
        for (Method m : methods) {
            if ("add".equals(m.getName())) {
                method = m;
            }
        }
        if (method == null) {
            throw new NoSuchFieldException();
        }
        method.setAccessible(true);
        method.invoke(CurveDB.class, "sm2p256v1", "1.2.156.10197.1.301", 1,
                "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
                "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
                "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
                "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
                1, splitPattern);

        final Field specCollection = CurveDB.class.getDeclaredField("specCollection");
        final Field oidMap = CurveDB.class.getDeclaredField("oidMap");
        oidMap.setAccessible(true);
        specCollection.setAccessible(true);
        specCollection.set(CurveDB.class, Collections.unmodifiableCollection(((Map) oidMap.get(CurveDB.class)).values()));

        Field nameTable = AlgorithmId.class.getDeclaredField("nameTable");
        nameTable.setAccessible(true);
        Map<ObjectIdentifier, String> map = (HashMap) nameTable.get(AlgorithmId.class);
        ObjectIdentifier objectIdentifier = ObjectIdentifier.newInternal(new int[]{1, 2, 156, 10197, 1, 501});
        map.put(objectIdentifier, ALGORITHM_SM2_KEY);

        Class clazz = Class.forName("io.netty.handler.ssl.ExtendedOpenSslSession");
        Field algorithmsField = clazz.getDeclaredField("LOCAL_SUPPORTED_SIGNATURE_ALGORITHMS");
        algorithmsField.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(algorithmsField, algorithmsField.getModifiers() & ~Modifier.FINAL);
        String[] algorithms = (String[]) algorithmsField.get(null);
        String[] newAlgorithms = new String[algorithms.length + 1];
        System.arraycopy(algorithms, 0, newAlgorithms, 0, algorithms.length);
        newAlgorithms[algorithms.length] = ALGORITHM_SM2_KEY;
        algorithmsField.set(null, newAlgorithms);

        String os = System.getProperty("os.name");
        if (os.toLowerCase().startsWith("win")) {
            loadLib("libcrypto-1_1-x64");
            loadLib("libssl-1_1-x64");
        }
    }

    private static void loadLib(String libName) throws IOException {
        String libExtension = ".dll";

        String libFullName = libName + libExtension;

        String nativeTempDir = System.getProperty("java.io.tmpdir");

        InputStream in = null;
        BufferedInputStream reader = null;
        FileOutputStream writer = null;

        File extractedLibFile = new File(nativeTempDir + File.separator + libFullName);
        if (!extractedLibFile.exists()) {
            try {
                in = ChainmakerX509CryptoSuite.class.getResourceAsStream("/win32-x86-64/" + libFullName);
                if (in == null) {
                    in = ChainmakerX509CryptoSuite.class.getResourceAsStream(libFullName);
                }
                ChainmakerX509CryptoSuite.class.getResource(libFullName);
                reader = new BufferedInputStream(in);
                writer = new FileOutputStream(extractedLibFile);

                byte[] buffer = new byte[1024];

                while (reader.read(buffer) > 0) {
                    writer.write(buffer);
                    buffer = new byte[1024];
                }
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (in != null) {
                    in.close();
                }
                if (writer != null) {
                    writer.close();
                }
            }
        }
        System.load(extractedLibFile.toString());
    }

}
