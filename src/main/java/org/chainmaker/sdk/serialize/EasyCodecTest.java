/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.serialize;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class EasyCodecTest {

    public static void main(String[] args) throws Exception {
        // unmarshal go marshal data
//        readFromFile();
        System.out.println("===================data===================");
        // data
        EasyCodecHelper helper = new EasyCodecHelper();
        helper.addInt("key1", 123);
        helper.addString("keyStr", "chainmaker长安链");
        helper.addBytes("bytes", "1".getBytes(StandardCharsets.UTF_8));

        // print data
        int val1 = helper.getInt("key1");
        String val2 = helper.getString("keyStr");
        byte[] val3 = helper.getBytes("bytes");
        System.out.println("key1=" + val1);
        System.out.println("keyStr=" + val2);
        System.out.println("bytes=" + new String(val3, StandardCharsets.UTF_8));
        for (int i = 0; i < val3.length; i++) {
            System.out.print(val3[i] + " ");
        }
        System.out.println();
        System.out.println("obj to json: " + helper.toJsonStr());

        // marshal
        System.out.println("===================marshal================");
        byte[] bytes = helper.EasyMarshal();
        System.out.println("marshal: " + bytes);
        for (int i = 0; i < bytes.length; i++) {
            System.out.print(bytes[i] + " ");
        }
//        writeToFile(bytes);
        System.out.println();

        // unmarshal
        System.out.println("===================unmarshal==============");
        EasyCodecHelper helper2 = EasyCodecHelper.EasyUnmarshal(bytes);
        System.out.println("obj to json: " + helper2.toJsonStr());

        byte[] val34 = helper2.getBytes("bytes");
        System.out.println("key1=" + helper2.getInt("key1"));
        System.out.println("keyStr=" + helper2.getString("keyStr"));
        System.out.println("bytes=" + new String(val34, StandardCharsets.UTF_8));
        for (int i = 0; i < val34.length; i++) {
            System.out.print(val34[i] + " ");
        }

        EasyCodecItem ii = new EasyCodecItem();
        ii.setValue("1".getBytes(StandardCharsets.UTF_8));
    }

    // go 写入文件，java读取文件并反序列化
    public static void readFromFile() throws IOException {
        System.out.println("===================readFileFromGo================");
        File file = new File("C:\\Users\\51578\\Desktop\\临时\\go-java-byte\\tmpGo");
        byte[] bytes = FileUtils.readFileToByteArray(file);
        EasyCodecHelper h = EasyCodecHelper.EasyUnmarshal(bytes);
        byte[] val3 = h.getBytes("bytes");
        System.out.println("bytes=" + new String(val3, StandardCharsets.UTF_8));
        for (int i = 0; i < val3.length; i++) {
            System.out.print(val3[i] + " ");
        }
        System.out.println("readFileFromGo unmarshal to json" + h.toJsonStr());
        System.out.println("===================readFileFromGo================");
    }

    // java写入文件，go读取文件并反序列化
    public static void writeToFile(byte[] bytes) throws IOException {
        System.out.println("===================writeToFile================");
        File file = new File("C:\\Users\\51578\\Desktop\\临时\\go-java-byte\\tmpJava");
        file.createNewFile();
        FileUtils.writeByteArrayToFile(file, bytes);
        System.out.println("===================writeToFile================");
    }

}
