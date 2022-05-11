/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.serialize;

public enum EasyType {
    EasyKeyTypeSystem(0),
    EasyKeyTypeUser(1),
    EasyValueTypeInt(0),
    EasyValueTypeString(1),
    EasyValueTypeBytes(2);

    private int type;

    EasyType(int type) {
        this.type = type;
    }

    public int type() {
        return this.type;
    }
}
