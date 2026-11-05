/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.security;

import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.buf.ByteChunk;

public class TestConstantTime {

    private static final String SECRET = "RIGHTSECRET";


    private static ByteChunk chunk(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.ISO_8859_1);
        ByteChunk bc = new ByteChunk();
        bc.setBytes(bytes, 0, bytes.length);
        return bc;
    }


    /*
     * The ByteChunk populated by the AJP connector is a view into the larger AJP packet buffer so the bytes of
     * interest do not start at index zero of the underlying array.
     */
    private static ByteChunk chunkWithOffset(String prefix, String s, String suffix) {
        byte[] bytes = (prefix + s + suffix).getBytes(StandardCharsets.ISO_8859_1);
        ByteChunk bc = new ByteChunk();
        bc.setBytes(bytes, prefix.length(), s.length());
        return bc;
    }


    @Test
    public void testByteChunkMatch() {
        Assert.assertTrue(ConstantTime.equals(chunk(SECRET), SECRET));
    }


    @Test
    public void testByteChunkMatchWithOffset() {
        Assert.assertTrue(ConstantTime.equals(chunkWithOffset("ABC", SECRET, "D\u00ff"), SECRET));
    }


    @Test
    public void testByteChunkOffsetDataNotCompared() {
        // The bytes before the start of the chunk match the secret - they must not be used in the comparison
        Assert.assertFalse(ConstantTime.equals(chunkWithOffset(SECRET, "WRONGSECRET", ""), SECRET));
    }


    @Test
    public void testByteChunkNearMissLastChar() {
        Assert.assertFalse(ConstantTime.equals(chunk("RIGHTSECRES"), SECRET));
        Assert.assertFalse(ConstantTime.equals(chunkWithOffset("XX", "RIGHTSECRES", "T"), SECRET));
    }


    @Test
    public void testByteChunkNearMissFirstChar() {
        Assert.assertFalse(ConstantTime.equals(chunk("SIGHTSECRET"), SECRET));
    }


    @Test
    public void testByteChunkPrefix() {
        Assert.assertFalse(ConstantTime.equals(chunk("RIGHTSECRE"), SECRET));
        Assert.assertFalse(ConstantTime.equals(chunk("R"), SECRET));
        // Shorter chunk at an offset where the following bytes would complete the secret
        Assert.assertFalse(ConstantTime.equals(chunkWithOffset("XX", "RIGHTSECRE", "T"), SECRET));
    }


    @Test
    public void testByteChunkLonger() {
        Assert.assertFalse(ConstantTime.equals(chunk("RIGHTSECRETX"), SECRET));
        Assert.assertFalse(ConstantTime.equals(chunk(SECRET + SECRET), SECRET));
    }


    @Test
    public void testByteChunkEmpty() {
        Assert.assertFalse(ConstantTime.equals(chunk(""), SECRET));
        Assert.assertFalse(ConstantTime.equals(chunk(SECRET), ""));
        Assert.assertTrue(ConstantTime.equals(chunk(""), ""));
    }


    @Test
    public void testByteChunkNull() {
        Assert.assertTrue(ConstantTime.equals((ByteChunk) null, null));
        Assert.assertFalse(ConstantTime.equals((ByteChunk) null, SECRET));
        Assert.assertFalse(ConstantTime.equals(chunk(SECRET), null));
    }


    @Test
    public void testByteChunkRecycled() {
        ByteChunk bc = chunk(SECRET);
        bc.recycle();
        Assert.assertFalse(ConstantTime.equals(bc, SECRET));
    }


    @Test
    public void testByteChunkHighBytes() {
        // Bytes >= 0x80 must be treated as unsigned (ISO-8859-1) values
        String s = "s\u00e9cr\u00e8t\u00ff\u0080";
        Assert.assertTrue(ConstantTime.equals(chunk(s), s));
        Assert.assertTrue(ConstantTime.equals(chunkWithOffset("\u00ff\u00fe", s, "\u0080"), s));
        Assert.assertFalse(ConstantTime.equals(chunk(s), "s\u00e9cr\u00e8t\u00ff\u0081"));
    }


    @Test
    public void testByteChunkHighBytesNoSignExtension() {
        // A sign-extended 0xE9 byte must not match a char value outside the ISO-8859-1 range
        byte[] bytes = new byte[] { (byte) 0xE9 };
        ByteChunk bc = new ByteChunk();
        bc.setBytes(bytes, 0, bytes.length);
        Assert.assertTrue(ConstantTime.equals(bc, "\u00e9"));
        Assert.assertFalse(ConstantTime.equals(bc, "\uffe9"));
        Assert.assertFalse(ConstantTime.equals(bc, "i"));
    }


    @Test
    public void testStringMatch() {
        Assert.assertTrue(ConstantTime.equals(SECRET, new String(SECRET), false));
        Assert.assertTrue(ConstantTime.equals(SECRET, SECRET, false));
    }


    @Test
    public void testStringMismatch() {
        Assert.assertFalse(ConstantTime.equals(SECRET, "RIGHTSECRES", false));
        Assert.assertFalse(ConstantTime.equals(SECRET, "RIGHTSECRE", false));
        Assert.assertFalse(ConstantTime.equals(SECRET, "RIGHTSECRETX", false));
        Assert.assertFalse(ConstantTime.equals(SECRET, "", false));
        Assert.assertFalse(ConstantTime.equals("", SECRET, false));
        Assert.assertTrue(ConstantTime.equals("", "", false));
    }


    @Test
    public void testStringIgnoreCase() {
        Assert.assertTrue(ConstantTime.equals(SECRET, "rightsecret", true));
        Assert.assertFalse(ConstantTime.equals(SECRET, "rightsecret", false));
        Assert.assertFalse(ConstantTime.equals(SECRET, "rightsecres", true));
    }


    @Test
    public void testStringNull() {
        Assert.assertTrue(ConstantTime.equals((String) null, null, false));
        Assert.assertFalse(ConstantTime.equals(SECRET, null, false));
        Assert.assertFalse(ConstantTime.equals(null, SECRET, false));
    }


    @Test
    public void testByteArray() {
        byte[] b1 = SECRET.getBytes(StandardCharsets.ISO_8859_1);
        byte[] b2 = SECRET.getBytes(StandardCharsets.ISO_8859_1);
        byte[] b3 = "RIGHTSECRES".getBytes(StandardCharsets.ISO_8859_1);
        byte[] b4 = "RIGHTSECRE".getBytes(StandardCharsets.ISO_8859_1);
        Assert.assertTrue(ConstantTime.equals(b1, b2));
        Assert.assertFalse(ConstantTime.equals(b1, b3));
        Assert.assertFalse(ConstantTime.equals(b1, b4));
        Assert.assertFalse(ConstantTime.equals(b4, b1));
    }
}
