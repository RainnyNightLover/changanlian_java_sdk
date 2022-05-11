/*
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package org.chainmaker.sdk.utils;

import com.google.common.io.Resources;
import org.apache.commons.io.IOUtils;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class FileUtils {
    private FileUtils() {
        throw new IllegalStateException("Utility class");
    }

    public static byte[] getResourceFileBytes(String resourcePath) throws UtilsException {

        byte[] fileBytes = null;
        try {
            fileBytes = IOUtils.toByteArray((BufferedInputStream) Resources.getResource(resourcePath).getContent());
        } catch (IOException e) {
            throw new UtilsException("get file by path err : " + e.getMessage());
        }
        return fileBytes;

    }

    public static byte[] getFileBytes(String filePath) throws UtilsException {
        byte[] fileBytes = null;
        try {
            fileBytes = IOUtils.toByteArray(new FileInputStream(new File(filePath)));
        } catch (IOException e) {
            throw new UtilsException("get file by path err : " + e.getMessage());
        }
        return fileBytes;
    }

    public static List<String> getFilesByPath(String path) {
        List<String> files = new ArrayList<>();
        File file = new File(path);
        File[] tempList = file.listFiles();
        if (tempList != null) {
            for (File value : tempList) {
                if (value.isFile() && value.getName().contains(".crt")) {
                    files.add(value.toString());
                }
            }
        }
        return files;
    }

    public static String getResourceFilePath(String resourcePath) {
        return System.getProperty("user.dir") + "/src/main/resources/" + resourcePath;
    }

    public static boolean isFileExist(String filePath) {
        File file = new File(filePath);
        return file.exists();
    }
}
