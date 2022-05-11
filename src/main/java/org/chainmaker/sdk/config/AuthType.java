/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/
package org.chainmaker.sdk.config;

public enum AuthType {

    PermissionedWithCert(1, "permissionedWithcert"),
    PermissionedWithKey(2, "permissionedWithKey"),
    Public(3, "public");

    private int code;
    private String msg;

    AuthType(int code, String msg) {
        this.code = code;
        this.msg = msg;
    }

    public int getCode() {
        return code;
    }

    public String getMsg() {
        return msg;
    }

    public static AuthType getByCode(int code) {
        for (AuthType template : AuthType.values()) {
            if (template.getCode() == code) {
                return template;
            }
        }
        return null;
    }
}
