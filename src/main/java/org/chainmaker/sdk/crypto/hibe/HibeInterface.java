/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.crypto.hibe;

import com.sun.jna.Library;
import org.chainmaker.sdk.crypto.hibe.gotype.GoBytes;
import org.chainmaker.sdk.crypto.hibe.gotype.GoString;

public interface HibeInterface extends Library {

    int HibeSetup(int depth, GoString.ByValue orgId, GoString.ByValue keyOutPath);

    int KeyGenFromMaster(GoString.ByValue id, GoString.ByValue keyOutPath,
                                               GoString.ByValue masterKeyFilePath, GoString.ByValue paramsFilePath);

    GoBytes.ByValue ReadKey(GoString.ByValue keyfilepath);

    GoBytes.ByValue EncryptHibeMsg(byte[] plainText, int textLen, byte[] receiverIds, int receiverIdsLen,
                                                         byte[] params, int paramsLen, int keyType);
    GoBytes.ByValue DecryptHibeMsg(byte[] localId, int localIdLen, byte[] params, int paramsLen,
                                                         byte[] privKey, int privKeyLen, byte[] hibeMsgMap, int hibeMsgMapLen, int keyType);
}
