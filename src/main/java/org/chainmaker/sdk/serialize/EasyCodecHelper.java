/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.serialize;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class EasyCodecHelper {

    // key可以重复
    private List<EasyCodecItem> items;
    // key重复则覆盖
    private Map<String, EasyCodecItem> map;

    public EasyCodecHelper() {
        this.items = new ArrayList<>();
        this.map = new HashMap<>();
    }

    public List<EasyCodecItem> getItems() {
        return this.items;
    }

    private void initMap() {
        if (map.size() == 0) {
            for (int i = 0; i < items.size(); i++) {
            }
        }
    }

    // key重复则取最后一个
    public int getInt(String key) {
        return (int) map.get(key).getValue();
    }

    // key重复则取最后一个
    public String getString(String key) {
        return String.valueOf(map.get(key).getValue());
    }

    // key重复则取最后一个
    public byte[] getBytes(String key) {
        return (byte[]) map.get(key).getValue();
    }

    public EasyCodecHelper addInt(String key, int val) {
        addItem(EasyType.EasyKeyTypeUser, key, EasyType.EasyValueTypeInt, val);
        return this;
    }

    public EasyCodecHelper addString(String key, String val) {
        addItem(EasyType.EasyKeyTypeUser, key, EasyType.EasyValueTypeString, val);
        return this;
    }

    public EasyCodecHelper addBytes(String key, byte[] val) {
        addItem(EasyType.EasyKeyTypeUser, key, EasyType.EasyValueTypeBytes, val);
        return this;
    }

    private void addItem(EasyType keyType, String key, EasyType valType, Object val) {
        EasyCodecItem item = new EasyCodecItem();
        item.setKeyType(keyType);
        item.setKey(key);
        item.setValueType(valType);
        item.setValue(val);
        this.items.add(item);
        this.map.put(item.getKey(), item);
    }

    public byte[] EasyMarshal() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] tmpBytes = null;

        // size
        out.write(intToByte(items.size()));
        for (int i = 0; i < items.size(); i++) {
            EasyCodecItem item = items.get(i);
            if (item.getKeyType() != EasyType.EasyKeyTypeSystem && item.getKeyType() != EasyType.EasyKeyTypeUser) {
                continue;
            }
            // key type
            out.write(intToByte(item.getKeyType().type()));
            tmpBytes = item.getKey().getBytes(StandardCharsets.UTF_8);
            // key len
            out.write(intToByte(tmpBytes.length));
            // key val
            out.write(tmpBytes);

            // val type
            out.write(intToByte(item.getValueType().type()));
            switch (item.getValueType()) {
                case EasyValueTypeInt:
                    int valInt = (int) item.getValue();
                    byte[] intBytes = intToByte(valInt);
                    out.write(intToByte(intBytes.length));
                    out.write(intBytes);
                    break;
                case EasyValueTypeString:
                    String valStr = String.valueOf(item.getValue());
                    byte[] strBytes = valStr.getBytes(StandardCharsets.UTF_8);
                    out.write(intToByte(strBytes.length));
                    out.write(strBytes);
                    break;
                case EasyValueTypeBytes:
                    byte[] bytes = (byte[]) item.getValue();
                    out.write(intToByte(bytes.length));
                    out.write(bytes);
                    break;
                default:
                    throw new RuntimeException("EasyCodec value type " + item.getValueType() + " no match");
            }
        }
        out.flush();
        return out.toByteArray();
    }

    public static EasyCodecHelper EasyUnmarshal(byte[] bytes) throws IOException {
        EasyCodecHelper helper = new EasyCodecHelper();
        ByteArrayInputStream is = new ByteArrayInputStream(bytes);

        int length = readInt(is);
//        System.out.println("length " + length);
        if (length > 100000) {
            throw new RuntimeException("length " + length);
        }
        if (length == 0) {
            return helper;
        }

        for (int i = 0; i < length; i++) {
            EasyCodecItem item = new EasyCodecItem();
            // key type
            int keyType = readInt(is);
            // key len
            int keyLen = readInt(is);
            // key
            byte[] keyBytes = new byte[keyLen];
            is.read(keyBytes);
            String key = new String(keyBytes, StandardCharsets.UTF_8);
            item.setKeyType(keyType == EasyType.EasyKeyTypeSystem.type() ? EasyType.EasyKeyTypeSystem : EasyType.EasyKeyTypeUser);
            item.setKey(key);

            // val type
            int valType = readInt(is);
            // val len
            int valLen = readInt(is);
            // val

            if (valType == EasyType.EasyValueTypeInt.type()) {
                int valInt = readInt(is);
                item.setValue(valInt);
            } else if (valType == EasyType.EasyValueTypeString.type()) {
                byte[] valBytes = new byte[valLen];
                is.read(valBytes);
                String valStr = new String(valBytes, StandardCharsets.UTF_8);
                item.setValue(valStr);
            } else if (valType == EasyType.EasyValueTypeBytes.type()) {
                byte[] valBytes = new byte[valLen];
                is.read(valBytes);
                item.setValue(valBytes);
            } else {
                throw new RuntimeException("EasyCodec value type " + valType + " no match");
            }
            helper.items.add(item);
            helper.map.put(item.getKey(), item);
        }

        return helper;
    }

    public String toJsonStr() {
        int len = this.items.size();
        String str = "{";
        for (int i = 0; i < len; i++) {
            EasyCodecItem item = this.items.get(i);
            str += "\"" + item.getKey() + "\":\"" + item.getValue() + "\",";
        }
        if (str.length() > 1) {
            str = str.substring(0, str.length() - 1);
        }
        str += "}";
        return str;
    }

    private static int readInt(ByteArrayInputStream is) throws IOException {
        byte[] bytes = new byte[4];
        is.read(bytes);
        return bytesToInt(bytes);
    }

    // 小端
    public static int bytesToInt(byte[] bytes) {
        int a = (bytes[0] & 0xff);
        int b = (bytes[1] & 0xff) << 8;
        int c = (bytes[3] & 0xff) << 24;
        int d = (bytes[2] & 0xff) << 16;
        return a | b | c | d;
    }

    // 小端
    public static byte[] intToByte(int n) {
        byte[] b = new byte[4];
        b[0] = (byte) (n & 0xff);
        b[1] = (byte) (n >> 8 & 0xff);
        b[2] = (byte) (n >> 16 & 0xff);//高字节在后是与java存放内存相反, 与书写顺序相反
        b[3] = (byte) (n >> 24 & 0xff);//数据组结束位,存放内存起始位, 即:高字节在后
        return b;
    }
}
