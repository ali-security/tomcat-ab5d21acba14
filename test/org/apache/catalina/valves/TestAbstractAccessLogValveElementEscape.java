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
package org.apache.catalina.valves;

import java.io.CharArrayWriter;
import java.util.Date;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.connector.Request;
import org.apache.catalina.valves.AbstractAccessLogValve.AccessLogElement;

/**
 * Checks that the request line (%r), query string (%q) and request URI (%U)
 * access log elements escape untrusted, client controlled values so that they
 * cannot be used to inject additional (forged) entries into the access log or
 * to break out of a quoted field.
 */
public class TestAbstractAccessLogValveElementEscape {

    private static final String UNICODE_ESCAPE_PREFIX = "\\" + "u";


    @Test
    public void testRequestLineEscapesUri() {
        String uri = "/foo\r\nbar\"baz\\qux\t";
        String result = format("%r", new LogRequest("GET", uri, null, "HTTP/1.1"));
        Assert.assertEquals("GET /foo\\r\\nbar\\\"baz\\\\qux\\t HTTP/1.1", result);
        assertNoRawControlChars(result);
    }


    @Test
    public void testRequestLineEscapesQuery() {
        String query = "a=1\r\nb=\"2\"&c=\\3";
        String result = format("%r", new LogRequest("GET", "/index.html", query, "HTTP/1.1"));
        Assert.assertEquals("GET /index.html?a=1\\r\\nb=\\\"2\\\"&c=\\\\3 HTTP/1.1", result);
        assertNoRawControlChars(result);
    }


    @Test
    public void testRequestLineEscapesOtherControlChars() {
        String uri = "/a" + (char) 0x07 + "b" + (char) 0x7f + "c" + (char) 0x0c;
        String result = format("%r", new LogRequest("GET", uri, null, "HTTP/1.1"));
        Assert.assertEquals("GET /a" + UNICODE_ESCAPE_PREFIX + "0007b" + UNICODE_ESCAPE_PREFIX + "007fc\\f HTTP/1.1",
                result);
        assertNoRawControlChars(result);
    }


    @Test
    public void testRequestLineForgedEntry() {
        // Attempt to inject a second, forged, access log entry and to break out
        // of the quoted request line field.
        String query = "x=1 HTTP/1.1\" 200 5\r\n10.0.0.1 - admin [01/Jan/2026:00:00:00 +0000] \"GET /admin";
        String result = format("\"%r\" %q", new LogRequest("GET", "/", query, "HTTP/1.1"));
        assertNoRawControlChars(result);
        // The only unescaped double quotes must be the two from the pattern
        Assert.assertEquals(2, countUnescapedQuotes(result));
        Assert.assertTrue(result, result.startsWith("\"GET /?x=1 HTTP/1.1\\\" 200 5\\r\\n10.0.0.1"));
        Assert.assertTrue(result, result.endsWith("\\\"GET /admin"));
    }


    @Test
    public void testRequestLineEmptyQuery() {
        String result = format("%r", new LogRequest("GET", "/", "", "HTTP/1.1"));
        Assert.assertEquals("GET /? HTTP/1.1", result);
    }


    @Test
    public void testRequestLineNullQuery() {
        String result = format("%r", new LogRequest("GET", "/", null, "HTTP/1.1"));
        Assert.assertEquals("GET / HTTP/1.1", result);
    }


    @Test
    public void testRequestLineNoMethod() {
        String result = format("%r", new LogRequest(null, "/", null, "HTTP/1.1"));
        Assert.assertEquals("-", result);
    }


    @Test
    public void testQueryEscapes() {
        String query = "a=1\r\nb=\"2\"&c=\\3\t";
        String result = format("%q", new LogRequest("GET", "/", query, "HTTP/1.1"));
        Assert.assertEquals("?a=1\\r\\nb=\\\"2\\\"&c=\\\\3\\t", result);
        assertNoRawControlChars(result);
    }


    @Test
    public void testQueryEscapesOtherControlChars() {
        String query = "a" + (char) 0x00 + "b" + (char) 0x1b + "c";
        String result = format("%q", new LogRequest("GET", "/", query, "HTTP/1.1"));
        Assert.assertEquals("?a" + UNICODE_ESCAPE_PREFIX + "0000b" + UNICODE_ESCAPE_PREFIX + "001bc", result);
        assertNoRawControlChars(result);
    }


    @Test
    public void testQueryEmpty() {
        String result = format("%q", new LogRequest("GET", "/", "", "HTTP/1.1"));
        Assert.assertEquals("?", result);
    }


    @Test
    public void testQueryNull() {
        String result = format("%q", new LogRequest("GET", "/", null, "HTTP/1.1"));
        Assert.assertEquals("", result);
    }


    @Test
    public void testQueryUnchanged() {
        String result = format("%q", new LogRequest("GET", "/", "data=123&x=%0D%0A", "HTTP/1.1"));
        Assert.assertEquals("?data=123&x=%0D%0A", result);
    }


    @Test
    public void testRequestUriEscapes() {
        String uri = "/foo\r\nbar\"baz\\qux";
        String result = format("%U", new LogRequest("GET", uri, null, "HTTP/1.1"));
        Assert.assertEquals("/foo\\r\\nbar\\\"baz\\\\qux", result);
        assertNoRawControlChars(result);
    }


    @Test
    public void testRequestUriForgedEntry() {
        String uri = "/a\n10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET /admin HTTP/1.1\" 200 5";
        String result = format("\"%U\"", new LogRequest("GET", uri, null, "HTTP/1.1"));
        assertNoRawControlChars(result);
        Assert.assertEquals(2, countUnescapedQuotes(result));
        Assert.assertEquals(
                "\"/a\\n10.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \\\"GET /admin HTTP/1.1\\\" 200 5\"", result);
    }


    @Test
    public void testRequestUriUnchanged() {
        String result = format("%U", new LogRequest("GET", "/level1/level2/foo.html", null, "HTTP/1.1"));
        Assert.assertEquals("/level1/level2/foo.html", result);
    }


    @Test
    public void testRequestUriNullRequest() {
        String result = format("%U", null);
        Assert.assertEquals("-", result);
    }


    private static String format(String pattern, Request request) {
        AccessLogValve valve = new AccessLogValve();
        valve.setPattern(pattern);
        CharArrayWriter buf = new CharArrayWriter();
        Date date = new Date();
        for (AccessLogElement element : valve.logElements) {
            element.addElement(buf, date, request, null, 0);
        }
        return buf.toString();
    }


    private static void assertNoRawControlChars(String result) {
        for (int i = 0; i < result.length(); i++) {
            char c = result.charAt(i);
            Assert.assertFalse("Unescaped control character [" + (int) c + "] at index [" + i + "] in [" + result +
                    "]", c < 32 || c == 127);
        }
    }


    private static int countUnescapedQuotes(String result) {
        int count = 0;
        boolean escaped = false;
        for (int i = 0; i < result.length(); i++) {
            char c = result.charAt(i);
            if (escaped) {
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
            } else if (c == '"') {
                count++;
            }
        }
        return count;
    }


    private static class LogRequest extends Request {

        private final String method;
        private final String requestURI;
        private final String queryString;
        private final String protocol;

        LogRequest(String method, String requestURI, String queryString, String protocol) {
            super(null);
            this.method = method;
            this.requestURI = requestURI;
            this.queryString = queryString;
            this.protocol = protocol;
        }

        @Override
        public String getMethod() {
            return method;
        }

        @Override
        public String getRequestURI() {
            return requestURI;
        }

        @Override
        public String getQueryString() {
            return queryString;
        }

        @Override
        public String getProtocol() {
            return protocol;
        }
    }
}
