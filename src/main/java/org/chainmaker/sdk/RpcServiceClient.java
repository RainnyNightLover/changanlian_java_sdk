/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/
package org.chainmaker.sdk;

import com.google.common.collect.ImmutableMap;
import io.grpc.ManagedChannel;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NegotiationType;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.handler.ssl.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.chainmaker.pb.api.RpcNodeGrpc;
import org.chainmaker.sdk.utils.Utils;
import org.chainmaker.sdk.utils.UtilsException;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static java.lang.String.format;

/*
 * RpcServiceClient is used to send transactions to chainmaker node
 */
public class RpcServiceClient {

    private Resource gmCaCert = new FileSystemResource("/Users/yangxing/IdeaProjects/sdk-java-changanlian/src/auth_new/ca/ca_cert.crt");
    private Resource gmSslCert = new FileSystemResource("/Users/yangxing/IdeaProjects/sdk-java-changanlian/src/auth_new/cli/sign-cert.pem");
    private Resource gmSslKey = new FileSystemResource("/Users/yangxing/IdeaProjects/sdk-java-changanlian/src/auth_new/cli/sign-pkcs8.key");
    private Resource gmEnSslCert = new FileSystemResource("/Users/yangxing/IdeaProjects/sdk-java-changanlian/src/auth_new/cli/enc-cert.pem");
    private Resource gmEnSslKey = new FileSystemResource("/Users/yangxing/IdeaProjects/sdk-java-changanlian/src/auth_new/cli/enc-pkcs8.key");

    private static final Map<Class<?>, Class<?>> WRAPPERS_TO_PRIM = new ImmutableMap.Builder<Class<?>, Class<?>>()
            .put(Boolean.class, boolean.class).put(Byte.class, byte.class).put(Character.class, char.class)
            .put(Double.class, double.class).put(Float.class, float.class).put(Integer.class, int.class)
            .put(Long.class, long.class).put(Short.class, short.class).put(Void.class, void.class).build();

    private ManagedChannel managedChannel;
    // async stub used to send transactions
    private RpcNodeGrpc.RpcNodeFutureStub rpcNodeFutureStub;
    // sync stub used to send transactions
    private RpcNodeGrpc.RpcNodeStub rpcNodeStub;

    public ManagedChannel getManagedChannel() {
        return managedChannel;
    }

    public void setManagedChannel(ManagedChannel managedChannel) {
        this.managedChannel = managedChannel;
    }

    public RpcNodeGrpc.RpcNodeFutureStub getRpcNodeFutureStub() {
        return rpcNodeFutureStub;
    }

    public void setRpcNodeFutureStub(RpcNodeGrpc.RpcNodeFutureStub rpcNodeFutureStub) {
        this.rpcNodeFutureStub = rpcNodeFutureStub;
    }

    public RpcNodeGrpc.RpcNodeStub getRpcNodeStub() {
        return rpcNodeStub;
    }

    public void setRpcNodeStub(RpcNodeGrpc.RpcNodeStub rpcNodeStub) {
        this.rpcNodeStub = rpcNodeStub;
    }

    // Construct RpcServiceClient object with node
    RpcServiceClient(Node node, User user, int messageSize) throws RpcServiceClientException, UtilsException {
        // managedChannel 从连接池里拿
        managedChannel = initManagedChannel(node, user, messageSize);
        rpcNodeFutureStub = RpcNodeGrpc.newFutureStub(managedChannel);
        rpcNodeStub = RpcNodeGrpc.newStub(managedChannel);
    }

    // New a RpcServiceClient with node
    public static RpcServiceClient newServiceClient(Node node, User user, int messageSize)
            throws RpcServiceClientException, UtilsException {
        return new RpcServiceClient(node, user, messageSize);
    }

    // Init managed channel
    private ManagedChannel initManagedChannel(Node node, User user, int messageSize)
            throws RpcServiceClientException, UtilsException {
        Properties grpcProperties = Utils.parseGrpcUrl(node.getGrpcUrl());
        String protocol = grpcProperties.getProperty("protocol");
        int port = Integer.parseInt(grpcProperties.getProperty("port"));
        String host = grpcProperties.getProperty("host");
        NettyChannelBuilder nettyChannelBuilder = NettyChannelBuilder.forAddress(host, port);

        if (messageSize > 0) {
            nettyChannelBuilder.maxInboundMessageSize(messageSize * 1024 * 1024);
            nettyChannelBuilder.maxInboundMetadataSize(messageSize * 1024 * 1024);
        }

        Properties nettyBuilderProperties = new Properties();
        nettyBuilderProperties.put("keepAliveTime", new Object[]{5L, TimeUnit.MINUTES});
        nettyBuilderProperties.put("keepAliveTimeout", new Object[]{8L, TimeUnit.SECONDS});
        nettyBuilderProperties.put("keepAliveWithoutCalls", new Object[]{true});

        try {
            if (protocol.equalsIgnoreCase("grpc")) {
                nettyChannelBuilder.usePlaintext(true);
                addNettyBuilderProps(nettyChannelBuilder, nettyBuilderProperties);
                return nettyChannelBuilder.build();
            }
            if (!protocol.equalsIgnoreCase("grpcs")) {
                throw new RpcServiceClientException("invalid protocol");
            }

            X509Certificate[] clientCert = new X509Certificate[]{(X509Certificate) user.getTlsCertificate()};
            PrivateKey clientKey = user.getTlsPrivateKey();
            final AbstractMap.SimpleImmutableEntry<PrivateKey, X509Certificate[]> clientTLSProps =
                    new AbstractMap.SimpleImmutableEntry<>(clientKey, clientCert);

            clientCert = clientTLSProps.getValue();
            clientKey = clientTLSProps.getKey();

            if (!"openSSL".equals(node.getSslProvider()) && !"JDK".equals(node.getSslProvider())) {
                throw new RpcServiceClientException(format("Endpoint %s property of sslProvider has to be either "
                        + "openSSL or JDK. value: '%s'", node.getGrpcUrl(), node.getSslProvider()));
            }

            if (!"TLS".equals(node.getNegotiationType()) && !"plainText".equals(node.getNegotiationType())) {
                throw new RpcServiceClientException(format("Endpoint %s property of negotiationType has to be either "
                        + "TLS or plainText. value: '%s'", node.getGrpcUrl(), node.getNegotiationType()));
            }
            if (node.getTlsCertBytes() == null) {
                throw new RpcServiceClientException("can't find tls cert");
            }

            SslProvider sslprovider = node.getSslProvider().equals("openSSL") ? SslProvider.OPENSSL : SslProvider.JDK;
            NegotiationType ntype = node.getNegotiationType().equals("TLS") ? NegotiationType.TLS : NegotiationType.PLAINTEXT;

            SslContextBuilder clientContextBuilder = getSslContextBuilder(clientCert, clientKey, sslprovider);

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            ArrayList<X509Certificate> x509CertificateList = new ArrayList<>();
            for (int i = 0; i < node.getTlsCertBytes().length; i++) {
                X509Certificate x509Certificate =
                        (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(node.getTlsCertBytes()[i]));
                x509CertificateList.add(x509Certificate);
            }

            X509Certificate[] x509Certificates = new X509Certificate[x509CertificateList.size()];

            /**fix SslContext here by java
             /*SslContext sslContext = clientContextBuilder
             .trustManager(x509CertificateList.toArray(x509Certificates))
             .build();*/
            SslContext sslContext = initSMSslContext();
            nettyChannelBuilder.sslContext(sslContext).negotiationType(ntype);
            if (node.getHostname() != null) {
                nettyChannelBuilder.overrideAuthority(node.getHostname());
            }

            addNettyBuilderProps(nettyChannelBuilder, nettyBuilderProperties);
        } catch (Exception e) {
            throw new RpcServiceClientException(e.toString());
        }
        return nettyChannelBuilder.build();
    }

    /**
     * init sm ssl context object
     *
     * @return
     * @throws IOException
     */
    public SslContext initSMSslContext()
            throws IOException, InvalidKeySpecException, CertificateException,
            NoSuchAlgorithmException, NoSuchProviderException {

        ApplicationProtocolConfig config = new ApplicationProtocolConfig(
                ApplicationProtocolConfig.Protocol.ALPN,
                ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                ApplicationProtocolNames.HTTP_2,
                ApplicationProtocolNames.HTTP_1_1);

        return SMSslClientContextTsingjFactory.build(
                config,
                gmCaCert.getInputStream(),
                gmEnSslCert.getInputStream(),
                gmEnSslKey.getInputStream(),
                gmSslCert.getInputStream(),
                gmSslKey.getInputStream());
    }

    // Init managed channel
    private ManagedChannel initManagedChannelBak(Node node, User user, int messageSize)
            throws RpcServiceClientException, UtilsException {
        Properties grpcProperties = Utils.parseGrpcUrl(node.getGrpcUrl());
        String protocol = grpcProperties.getProperty("protocol");
        int port = Integer.parseInt(grpcProperties.getProperty("port"));
        String host = grpcProperties.getProperty("host");
        NettyChannelBuilder nettyChannelBuilder = NettyChannelBuilder.forAddress(host, port);

        if (messageSize > 0) {
            nettyChannelBuilder.maxInboundMessageSize(messageSize * 1024 * 1024);
            nettyChannelBuilder.maxInboundMetadataSize(messageSize * 1024 * 1024);
        }

        Properties nettyBuilderProperties = new Properties();
        nettyBuilderProperties.put("keepAliveTime", new Object[]{5L, TimeUnit.MINUTES});
        nettyBuilderProperties.put("keepAliveTimeout", new Object[]{8L, TimeUnit.SECONDS});
        nettyBuilderProperties.put("keepAliveWithoutCalls", new Object[]{true});

        try {
            if (protocol.equalsIgnoreCase("grpc")) {
                nettyChannelBuilder.usePlaintext(true);
                addNettyBuilderProps(nettyChannelBuilder, nettyBuilderProperties);
                return nettyChannelBuilder.build();
            }
            if (!protocol.equalsIgnoreCase("grpcs")) {
                throw new RpcServiceClientException("invalid protocol");
            }

            X509Certificate[] clientCert = new X509Certificate[]{(X509Certificate) user.getTlsCertificate()};
            PrivateKey clientKey = user.getTlsPrivateKey();
            final AbstractMap.SimpleImmutableEntry<PrivateKey, X509Certificate[]> clientTLSProps =
                    new AbstractMap.SimpleImmutableEntry<>(clientKey, clientCert);

            clientCert = clientTLSProps.getValue();
            clientKey = clientTLSProps.getKey();

            if (!"openSSL".equals(node.getSslProvider()) && !"JDK".equals(node.getSslProvider())) {
                throw new RpcServiceClientException(format("Endpoint %s property of sslProvider has to be either "
                        + "openSSL or JDK. value: '%s'", node.getGrpcUrl(), node.getSslProvider()));
            }

            if (!"TLS".equals(node.getNegotiationType()) && !"plainText".equals(node.getNegotiationType())) {
                throw new RpcServiceClientException(format("Endpoint %s property of negotiationType has to be either "
                        + "TLS or plainText. value: '%s'", node.getGrpcUrl(), node.getNegotiationType()));
            }
            if (node.getTlsCertBytes() == null) {
                throw new RpcServiceClientException("can't find tls cert");
            }

            SslProvider sslprovider = node.getSslProvider().equals("openSSL") ? SslProvider.OPENSSL : SslProvider.JDK;
            NegotiationType ntype = node.getNegotiationType().equals("TLS") ? NegotiationType.TLS : NegotiationType.PLAINTEXT;

            SslContextBuilder clientContextBuilder = getSslContextBuilder(clientCert, clientKey, sslprovider);

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            ArrayList<X509Certificate> x509CertificateList = new ArrayList<>();
            for (int i = 0; i < node.getTlsCertBytes().length; i++) {
                X509Certificate x509Certificate =
                        (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(node.getTlsCertBytes()[i]));
                x509CertificateList.add(x509Certificate);
            }

            X509Certificate[] x509Certificates = new X509Certificate[x509CertificateList.size()];
            SslContext sslContext = clientContextBuilder
                    .trustManager(x509CertificateList.toArray(x509Certificates))
                    .build();
            nettyChannelBuilder.sslContext(sslContext).negotiationType(ntype);
            if (node.getHostname() != null) {
                nettyChannelBuilder.overrideAuthority(node.getHostname());
            }

            addNettyBuilderProps(nettyChannelBuilder, nettyBuilderProperties);
        } catch (Exception e) {
            throw new RpcServiceClientException(e.toString());
        }
        return nettyChannelBuilder.build();
    }

    private static X509Certificate getX509Certificate(byte[] pemCertificate) throws RpcServiceClientException {
        X509Certificate ret = null;

        List<Provider> providerList = new LinkedList<>(Arrays.asList(Security.getProviders()));
        try {
            providerList.add(BouncyCastleProvider.class.newInstance()); // bouncy castle is there always.
        } catch (Exception e) {
            throw new RpcServiceClientException(e.toString());
        }
        for (Provider provider : providerList) {
            try {
                if (null == provider) {
                    continue;
                }
                CertificateFactory certFactory = CertificateFactory.getInstance("X.509", provider);
                try (ByteArrayInputStream bis = new ByteArrayInputStream(pemCertificate)) {
                    Certificate certificate = certFactory.generateCertificate(bis);
                    if (certificate instanceof X509Certificate) {
                        ret = (X509Certificate) certificate;
                        break;
                    }
                }
            } catch (Exception e) {
                throw new RpcServiceClientException(e.toString());
            }
        }

        return ret;
    }

    /**
     * yangxing used for build the safe connection things
     *
     * @param clientCert
     * @param clientKey
     * @param sslprovider
     * @return
     */
    private static SslContextBuilder getSslContextBuilder(X509Certificate[] clientCert, PrivateKey clientKey, SslProvider sslprovider) {
        SslContextBuilder clientContextBuilder = GrpcSslContexts.configure(SslContextBuilder.forClient(), sslprovider);
        if (clientKey != null && clientCert != null) {
            clientContextBuilder = clientContextBuilder.keyManager(clientKey, clientCert);
        }
        return clientContextBuilder;
    }

    private void addNettyBuilderProps(NettyChannelBuilder channelBuilder, Properties props)
            throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        if (props == null) {
            return;
        }

        for (Map.Entry<?, ?> es : props.entrySet()) {
            Object methodprop = es.getKey();
            if (methodprop == null) {
                continue;
            }
            String methodName = String.valueOf(methodprop);
            Object parmsArrayO = es.getValue();
            Object[] parmsArray;
            if (!(parmsArrayO instanceof Object[])) {
                parmsArray = new Object[]{parmsArrayO};
            } else {
                parmsArray = (Object[]) parmsArrayO;
            }

            Class<?>[] classParams = getClassParams(parmsArray);
            final Method method = channelBuilder.getClass().getMethod(methodName, classParams);

            method.invoke(channelBuilder, parmsArray);
        }
    }

    private Class<?>[] getClassParams(Object[] parmsArray) {
        Class<?>[] classParams = new Class[parmsArray.length];
        int i = -1;
        for (Object oparm : parmsArray) {
            ++i;
            if (null == oparm) {
                classParams[i] = Object.class;
                continue;
            }

            Class<?> unwrapped = WRAPPERS_TO_PRIM.get(oparm.getClass());
            if (null != unwrapped) {
                classParams[i] = unwrapped;
                continue;
            }

            Class<?> clz = oparm.getClass();

            Class<?> ecz = clz.getEnclosingClass();
            if (null != ecz && ecz.isEnum()) {
                clz = ecz;
            }
            classParams[i] = clz;
        }
        return classParams;
    }
}
