package io.netty.handler.ssl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

/*** description:
 **/
public class SMSslClientContextTsingjFactory {

    private static final Logger logger = LoggerFactory.getLogger(SMSslClientContextTsingjFactory.class);

    /**
     * Create an SMSslClientTsingjContext object
     *
     * @param caCert          gmca.crt file absolute path
     * @param encryptNodeCert gmensdk.crt file absolute path
     * @param encryptNodeKey  gmensdk.key file absolute path
     * @param nodeCert        gmsdk.crt file absolute path
     * @param nodeKey         gmsdk.key file absolute path
     * @return SMSslClientTsingjContext
     */
    public static SMSslClientTsingjContext build(
            ApplicationProtocolConfig apnCfg,
            String caCert, String encryptNodeCert, String encryptNodeKey, String nodeCert, String nodeKey)
            throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeySpecException {
        return build(
                apnCfg,
                new File(caCert),
                new File(encryptNodeCert),
                new File(encryptNodeKey),
                new File(nodeCert),
                new File(nodeKey));
    }

    /**
     * Create an SMSslClientTsingjContext object
     *
     * @param caCert          gmca.crt file absolute path
     * @param encryptNodeCert gmensdk.crt file absolute path
     * @param encryptNodeKey  gmensdk.key file absolute path
     * @param nodeCert        gmsdk.crt file absolute path
     * @param nodeKey         gmsdk.key file absolute path
     * @return SMSslClientTsingjContext
     */
    public static SMSslClientTsingjContext build(
            ApplicationProtocolConfig apnCfg,
            File caCert, File encryptNodeCert, File encryptNodeKey, File nodeCert, File nodeKey)
            throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeySpecException {

        logger.info(
                "caCert: {}, encryptNodeCert: {}, encryptNodeKey: {}, nodeCert: {}, nodeKey: {}",
                caCert,
                encryptNodeCert,
                encryptNodeKey,
                nodeCert,
                nodeKey);

        X509Certificate[] caX509Certificates = SMPemTool.toX509Certificates(caCert);
        X509Certificate[] encryptNodeX509Certificates = SMPemTool.toX509Certificates(encryptNodeCert);
        PrivateKey encryptNodePrivateKey = SMPemTool.toPrivateKey(encryptNodeKey);
        X509Certificate[] nodeX509Certificates = SMPemTool.toX509Certificates(nodeCert);
        PrivateKey nodePrivateKey = SMPemTool.toPrivateKey(nodeKey);

        return new SMSslClientTsingjContext(
                apnCfg,
                caX509Certificates,
                encryptNodeX509Certificates,
                encryptNodePrivateKey,
                nodeX509Certificates,
                nodePrivateKey);
    }

    /**
     * Create an SMSslClientTsingjContext object
     *
     * @param caCert          gmca.crt input stream
     * @param encryptNodeCert gmensdk.crt input stream
     * @param encryptNodeKey  gmensdk.key input stream
     * @param nodeCert        gmsdk.crt input stream
     * @param nodeKey         gmsdk.key input stream
     * @return SMSslClientTsingjContext
     */
    public static SMSslClientTsingjContext build(
            ApplicationProtocolConfig apnCfg,
            InputStream caCert,
            InputStream encryptNodeCert,
            InputStream encryptNodeKey,
            InputStream nodeCert,
            InputStream nodeKey)
            throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException,
            InvalidKeySpecException {

        logger.info(
                "caCert: {}, encryptNodeCert: {}, encryptNodeKey: {}, nodeCert: {}, nodeKey: {}",
                caCert,
                encryptNodeCert,
                encryptNodeKey,
                nodeCert,
                nodeKey);

        X509Certificate[] caX509Certificates = SMPemTool.toX509Certificates(caCert);
        X509Certificate[] encryptNodeX509Certificates = SMPemTool.toX509Certificates(encryptNodeCert);
        PrivateKey encryptNodePrivateKey = SMPemTool.toPrivateKey(encryptNodeKey);
        X509Certificate[] nodeX509Certificates = SMPemTool.toX509Certificates(nodeCert);
        PrivateKey nodePrivateKey = SMPemTool.toPrivateKey(nodeKey);

        return new SMSslClientTsingjContext(
                apnCfg,
                caX509Certificates,
                encryptNodeX509Certificates,
                encryptNodePrivateKey,
                nodeX509Certificates,
                nodePrivateKey);
    }

}
