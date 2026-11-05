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
package org.apache.tomcat.util.net.openssl.panama;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandle;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Locale;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.catalina.core.OpenSSLLifecycleListener;
import org.apache.tomcat.util.compat.JreCompat;
import org.apache.tomcat.util.net.TesterSupport;

/**
 * Checks that internal errors while obtaining an OCSP response (unreachable
 * responder, HTTP errors, timeouts, oversized responses) are reported as
 * X509_V_ERR_UNABLE_TO_GET_CRL so that they are treated as a soft failure
 * rather than as a hard verification failure, and that the size of the
 * response read from the responder is bounded.
 * <p>
 * The test sources are compiled for Java 8 so all access to the FFM API and to
 * the FFM based OpenSSL classes is via reflection.
 */
public class TestOpenSSLEngineOcspInternalError {

    private static final int OVERSIZED_LENGTH = 64 * 1024 * 1024;
    private static final int DEFAULT_TIMEOUT = 5000;
    private static final int SHORT_TIMEOUT = 1000;

    private static Object nullSegment;
    private static Object javaByteLayout;
    private static Object addressLayout;
    private static Method arenaOfConfined;
    private static Method allocateBytes;
    private static Method allocateAddress;
    private static Method d2iX509;
    private static Method x509Free;
    private static Method storeCtxGetError;
    private static Method storeCtxSetError;
    private static MethodHandle storeCtxNew;
    private static MethodHandle storeCtxFree;
    private static Constructor<?> engineStateConstructor;
    private static Method processOCSPRequest;
    private static int errUnableToGetCrl;
    private static int errApplicationVerification;
    private static int certStatusUnknown;


    @BeforeClass
    public static void setup() throws Exception {
        Assume.assumeTrue("FFM requires Java 22 or later", JreCompat.isJre22Available());
        new OpenSSLLifecycleListener();
        Assume.assumeTrue("OpenSSL is not available via FFM", OpenSSLLifecycleListener.isAvailable());

        Class<?> compatClass = Class.forName("org.apache.tomcat.util.openssl.openssl_h_Compatibility");
        Assume.assumeFalse("OCSP is not supported with BoringSSL", compatClass.getField("BORINGSSL").getBoolean(null));

        Class<?> memorySegmentClass = Class.forName("java.lang.foreign.MemorySegment");
        Class<?> memoryLayoutClass = Class.forName("java.lang.foreign.MemoryLayout");
        Class<?> valueLayoutClass = Class.forName("java.lang.foreign.ValueLayout");
        Class<?> arenaClass = Class.forName("java.lang.foreign.Arena");
        Class<?> functionDescriptorClass = Class.forName("java.lang.foreign.FunctionDescriptor");
        Class<?> linkerClass = Class.forName("java.lang.foreign.Linker");
        Class<?> linkerOptionClass = Class.forName("java.lang.foreign.Linker$Option");

        nullSegment = memorySegmentClass.getField("NULL").get(null);
        javaByteLayout = valueLayoutClass.getField("JAVA_BYTE").get(null);
        addressLayout = valueLayoutClass.getField("ADDRESS").get(null);
        arenaOfConfined = arenaClass.getMethod("ofConfined");
        allocateBytes = arenaClass.getMethod("allocateFrom",
                Class.forName("java.lang.foreign.ValueLayout$OfByte"), byte[].class);
        allocateAddress = arenaClass.getMethod("allocateFrom",
                Class.forName("java.lang.foreign.AddressLayout"), memorySegmentClass);

        Class<?> opensslClass = Class.forName("org.apache.tomcat.util.openssl.openssl_h");
        d2iX509 = opensslClass.getMethod("d2i_X509", memorySegmentClass, memorySegmentClass, long.class);
        x509Free = opensslClass.getMethod("X509_free", memorySegmentClass);
        storeCtxGetError = opensslClass.getMethod("X509_STORE_CTX_get_error", memorySegmentClass);
        storeCtxSetError = opensslClass.getMethod("X509_STORE_CTX_set_error", memorySegmentClass, int.class);
        errUnableToGetCrl = ((Integer) opensslClass.getMethod("X509_V_ERR_UNABLE_TO_GET_CRL").invoke(null)).intValue();
        errApplicationVerification =
                ((Integer) opensslClass.getMethod("X509_V_ERR_APPLICATION_VERIFICATION").invoke(null)).intValue();
        certStatusUnknown = ((Integer) opensslClass.getMethod("V_OCSP_CERTSTATUS_UNKNOWN").invoke(null)).intValue();

        // X509_STORE_CTX_new and X509_STORE_CTX_free are not part of the generated API
        Method findOrThrow = opensslClass.getDeclaredMethod("findOrThrow", String.class);
        findOrThrow.setAccessible(true);
        Object linker = linkerClass.getMethod("nativeLinker").invoke(null);
        Method downcallHandle = linkerClass.getMethod("downcallHandle", memorySegmentClass, functionDescriptorClass,
                Array.newInstance(linkerOptionClass, 0).getClass());
        Class<?> memoryLayoutArrayClass = Array.newInstance(memoryLayoutClass, 0).getClass();
        Object noArguments = Array.newInstance(memoryLayoutClass, 0);
        Object addressArgument = Array.newInstance(memoryLayoutClass, 1);
        Array.set(addressArgument, 0, addressLayout);
        Object newDescriptor = functionDescriptorClass.getMethod("of", memoryLayoutClass, memoryLayoutArrayClass)
                .invoke(null, addressLayout, noArguments);
        Object freeDescriptor =
                functionDescriptorClass.getMethod("ofVoid", memoryLayoutArrayClass).invoke(null, addressArgument);
        Object noOptions = Array.newInstance(linkerOptionClass, 0);
        storeCtxNew = (MethodHandle) downcallHandle.invoke(linker, findOrThrow.invoke(null, "X509_STORE_CTX_new"),
                newDescriptor, noOptions);
        storeCtxFree = (MethodHandle) downcallHandle.invoke(linker, findOrThrow.invoke(null, "X509_STORE_CTX_free"),
                freeDescriptor, noOptions);

        Class<?> engineClass = Class.forName("org.apache.tomcat.util.net.openssl.panama.OpenSSLEngine");
        Class<?> engineStateClass = Class.forName("org.apache.tomcat.util.net.openssl.panama.OpenSSLEngine$EngineState");
        engineStateConstructor = engineStateClass.getDeclaredConstructor(memorySegmentClass, memorySegmentClass,
                int.class, boolean.class, int.class, int.class);
        engineStateConstructor.setAccessible(true);
        processOCSPRequest = engineClass.getDeclaredMethod("processOCSPRequest", engineStateClass, URL.class,
                memorySegmentClass, memorySegmentClass, memorySegmentClass, arenaClass);
        processOCSPRequest.setAccessible(true);
    }


    @Test
    public void testHttpInternalServerError() throws Throwable {
        try (RawOcspResponder responder = new RawOcspResponder(Mode.HTTP_500)) {
            int[] result = doOcspRequest(responder.getUrl(), DEFAULT_TIMEOUT);
            assertSoftFail(result);
        }
    }


    @Test
    public void testConnectionRefused() throws Throwable {
        int port;
        try (ServerSocket serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            port = serverSocket.getLocalPort();
        }
        int[] result = doOcspRequest(new URL("http://127.0.0.1:" + port + "/ocsp"), DEFAULT_TIMEOUT);
        assertSoftFail(result);
    }


    @Test
    public void testReadTimeout() throws Throwable {
        try (RawOcspResponder responder = new RawOcspResponder(Mode.NO_RESPONSE)) {
            int[] result = doOcspRequest(responder.getUrl(), SHORT_TIMEOUT);
            assertSoftFail(result);
        }
    }


    @Test
    public void testOversizedResponse() throws Throwable {
        long written;
        int[] result;
        try (RawOcspResponder responder = new RawOcspResponder(Mode.OVERSIZED)) {
            result = doOcspRequest(responder.getUrl(), DEFAULT_TIMEOUT);
            responder.close();
            written = responder.getBodyBytesWritten();
        }
        assertSoftFail(result);
        // The client must stop reading well before the end of the response
        Assert.assertTrue("Response body was read in full (" + written + " bytes)", written < OVERSIZED_LENGTH);
    }


    @Test
    public void testOcspInternalErrorStatus() throws Throwable {
        try (RawOcspResponder responder = new RawOcspResponder(Mode.OCSP_INTERNAL_ERROR)) {
            int[] result = doOcspRequest(responder.getUrl(), DEFAULT_TIMEOUT);
            assertSoftFail(result);
        }
    }


    @Test
    public void testInvalidResponse() throws Throwable {
        try (RawOcspResponder responder = new RawOcspResponder(Mode.GARBAGE)) {
            int[] result = doOcspRequest(responder.getUrl(), DEFAULT_TIMEOUT);
            Assert.assertEquals(certStatusUnknown, result[0]);
            // A response that cannot be parsed remains a hard failure
            Assert.assertEquals(errApplicationVerification, result[1]);
        }
    }


    private static void assertSoftFail(int[] result) {
        Assert.assertEquals(certStatusUnknown, result[0]);
        Assert.assertEquals("OCSP internal error must be reported as X509_V_ERR_UNABLE_TO_GET_CRL", errUnableToGetCrl,
                result[1]);
    }


    /*
     * Returns the OCSP certificate status and the error set on the
     * X509_STORE_CTX.
     */
    private static int[] doOcspRequest(URL url, int ocspTimeout) throws Throwable {
        Object arena = arenaOfConfined.invoke(null);
        Object x509ctx = nullSegment;
        Object x509 = nullSegment;
        Object issuer = nullSegment;
        try {
            x509 = loadCertificate(arena, TesterSupport.LOCALHOST_RSA_CERT_PEM);
            issuer = loadCertificate(arena, TesterSupport.CA_CERT_PEM);
            x509ctx = storeCtxNew.invokeWithArguments();
            Assert.assertNotEquals(nullSegment, x509ctx);
            storeCtxSetError.invoke(null, x509ctx, Integer.valueOf(0));
            Object state = engineStateConstructor.newInstance(nullSegment, nullSegment, Integer.valueOf(10),
                    Boolean.FALSE, Integer.valueOf(ocspTimeout), Integer.valueOf(0));
            int status;
            try {
                status = ((Integer) processOCSPRequest.invoke(null, state, url, issuer, x509, x509ctx, arena))
                        .intValue();
            } catch (InvocationTargetException e) {
                throw e.getCause();
            }
            int error = ((Integer) storeCtxGetError.invoke(null, x509ctx)).intValue();
            return new int[] { status, error };
        } finally {
            if (!nullSegment.equals(x509ctx)) {
                storeCtxFree.invokeWithArguments(x509ctx);
            }
            if (!nullSegment.equals(x509)) {
                x509Free.invoke(null, x509);
            }
            if (!nullSegment.equals(issuer)) {
                x509Free.invoke(null, issuer);
            }
            ((AutoCloseable) arena).close();
        }
    }


    private static Object loadCertificate(Object arena, String pemFile) throws Exception {
        byte[] der;
        try (InputStream is = new FileInputStream(pemFile)) {
            der = CertificateFactory.getInstance("X.509").generateCertificate(is).getEncoded();
        }
        Object derSegment = allocateBytes.invoke(arena, javaByteLayout, der);
        Object derPointer = allocateAddress.invoke(arena, addressLayout, derSegment);
        Object x509 = d2iX509.invoke(null, nullSegment, derPointer, Long.valueOf(der.length));
        Assert.assertNotEquals(nullSegment, x509);
        return x509;
    }


    private enum Mode {
        HTTP_500,
        NO_RESPONSE,
        OVERSIZED,
        OCSP_INTERNAL_ERROR,
        GARBAGE
    }


    /*
     * Minimal HTTP server that handles a single OCSP request with a fixed,
     * misbehaving response.
     */
    private static final class RawOcspResponder implements Runnable, Closeable {

        private final Mode mode;
        private final ServerSocket serverSocket;
        private final Thread thread;
        private volatile Socket socket;
        private volatile long bodyBytesWritten = 0;

        private RawOcspResponder(Mode mode) throws IOException {
            this.mode = mode;
            serverSocket = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
            thread = new Thread(this, "RawOcspResponder-" + mode);
            thread.setDaemon(true);
            thread.start();
        }

        private URL getUrl() throws IOException {
            return new URL("http://127.0.0.1:" + serverSocket.getLocalPort() + "/ocsp");
        }

        private long getBodyBytesWritten() {
            return bodyBytesWritten;
        }

        @Override
        public void run() {
            try (Socket s = serverSocket.accept()) {
                socket = s;
                InputStream is = s.getInputStream();
                readRequest(is);
                OutputStream os = s.getOutputStream();
                switch (mode) {
                    case HTTP_500:
                        os.write(("HTTP/1.1 500 Internal Server Error\r\n" + "Content-Length: 0\r\n" +
                                "Connection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
                        os.flush();
                        break;
                    case NO_RESPONSE:
                        // Never respond. Wait for the client to give up.
                        while (is.read() != -1) {
                            // Ignore
                        }
                        break;
                    case OVERSIZED:
                        writeOkHeaders(os, OVERSIZED_LENGTH);
                        byte[] chunk = new byte[8192];
                        Arrays.fill(chunk, (byte) 0x30);
                        long total = 0;
                        while (total < OVERSIZED_LENGTH) {
                            os.write(chunk);
                            total += chunk.length;
                            bodyBytesWritten = total;
                        }
                        os.flush();
                        break;
                    case OCSP_INTERNAL_ERROR:
                        // OCSPResponse with responseStatus internalError (2)
                        byte[] internalError = new byte[] { 0x30, 0x03, 0x0A, 0x01, 0x02 };
                        writeOkHeaders(os, internalError.length);
                        os.write(internalError);
                        os.flush();
                        break;
                    case GARBAGE:
                        byte[] garbage =
                                "This is not a DER encoded OCSP response".getBytes(StandardCharsets.ISO_8859_1);
                        writeOkHeaders(os, garbage.length);
                        os.write(garbage);
                        os.flush();
                        break;
                }
            } catch (IOException ioe) {
                // Expected when the client stops reading or closes the connection
            }
        }

        private static void writeOkHeaders(OutputStream os, int contentLength) throws IOException {
            os.write(("HTTP/1.1 200 OK\r\n" + "Content-Type: application/ocsp-response\r\n" + "Content-Length: " +
                    contentLength + "\r\n" + "Connection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
        }

        private static void readRequest(InputStream is) throws IOException {
            ByteArrayOutputStream headers = new ByteArrayOutputStream();
            int state = 0;
            while (state < 4) {
                int b = is.read();
                if (b == -1) {
                    throw new IOException("Unexpected end of request headers");
                }
                headers.write(b);
                if ((b == '\r' && (state == 0 || state == 2)) || (b == '\n' && (state == 1 || state == 3))) {
                    state++;
                } else if (b == '\r') {
                    state = 1;
                } else {
                    state = 0;
                }
            }
            int contentLength = 0;
            String[] lines = new String(headers.toByteArray(), StandardCharsets.ISO_8859_1).split("\r\n");
            for (String line : lines) {
                int colon = line.indexOf(':');
                if (colon > 0 && "content-length".equals(line.substring(0, colon).trim().toLowerCase(Locale.ENGLISH))) {
                    contentLength = Integer.parseInt(line.substring(colon + 1).trim());
                }
            }
            for (int i = 0; i < contentLength; i++) {
                if (is.read() == -1) {
                    throw new IOException("Unexpected end of request body");
                }
            }
        }

        @Override
        public void close() throws IOException {
            serverSocket.close();
            Socket s = socket;
            if (s != null) {
                s.close();
            }
            try {
                thread.join(10000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
}
