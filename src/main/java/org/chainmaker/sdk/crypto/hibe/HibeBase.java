/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.crypto.hibe;

import com.sun.jna.Native;
import org.chainmaker.sdk.crypto.ChainMakerCryptoSuiteException;

public class HibeBase {

    static final String LIBRARY_NAME = "hibe";
    public static HibeInterface instance = null;

    public static HibeInterface getHibeInterface() throws ChainMakerCryptoSuiteException {
        if (instance != null) {
            return instance;
        }

        try {
            instance = (HibeInterface) Native.load(LIBRARY_NAME, HibeInterface.class);
        } catch (Exception e) {
            throw new ChainMakerCryptoSuiteException("native load hibe err : " + e.getMessage());
        }

        return instance;
    }

}
