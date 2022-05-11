/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.crypto.hibe.gotype;

import com.sun.jna.Structure;

import java.io.UnsupportedEncodingException;

/**
 * GoString map to UTF-8 encoded string
 */
@Structure.FieldOrder({"p", "n"})
public class GoString extends Structure {
    public static class ByValue extends GoString implements Structure.ByValue {
        public ByValue() {
        }

        public ByValue(String s) throws UnsupportedEncodingException {
            this.p = s;
            this.n = s.getBytes(Constants.UTF8).length;
        }
    }

    public String p;
    public long n;
}