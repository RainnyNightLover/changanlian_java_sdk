/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.crypto.hibe.gotype;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public class GoBytes extends Structure {
    public static class ByValue extends GoBytes implements Structure.ByValue {
    }

    public Pointer r0;
    public long r1;

    protected List<String> getFieldOrder() {
        return Arrays.asList(new String[]{"r0", "r1"});
    }
}