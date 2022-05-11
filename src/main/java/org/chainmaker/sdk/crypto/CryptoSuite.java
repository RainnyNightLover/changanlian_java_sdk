/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.crypto;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Collection;

public interface CryptoSuite {

    void loadCACertificates(Collection<Certificate> certificates) throws ChainMakerCryptoSuiteException;

    void loadCACertificatesAsBytes(Collection<byte[]> certificates) throws ChainMakerCryptoSuiteException;

    KeyPair keyGen() throws ChainMakerCryptoSuiteException;

    byte[] sign(PrivateKey privateKey, byte[] plainText) throws ChainMakerCryptoSuiteException;

    byte[] rsaSign(PrivateKey privateKey, byte[] plainText) throws ChainMakerCryptoSuiteException;

    boolean verify(Certificate certificate, byte[] signature, byte[] plainText) throws ChainMakerCryptoSuiteException;

    byte[] hash(byte[] plainText) throws ChainMakerCryptoSuiteException;

    Certificate getCertificateFromBytes(byte[] certBytes) throws ChainMakerCryptoSuiteException;
}
