/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.serialize;

public class EasyCodecItem {
    private EasyType keyType;
    private String key;
    private EasyType valueType;
    private Object value;

    public EasyType getKeyType() {
        return keyType;
    }

    public void setKeyType(EasyType keyType) {
        this.keyType = keyType;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public EasyType getValueType() {
        return valueType;
    }

    public void setValueType(EasyType valueType) {
        this.valueType = valueType;
    }

    public Object getValue() {
        return value;
    }

    public void setValue(Object value) {
        this.value = value;
    }
}
