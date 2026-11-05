/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.coyote.http2;

import java.nio.ByteBuffer;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.http.MimeHeaders;

/**
 * Tests the interaction between the HPACK decoder's header emitter and stream replacement in
 * {@link Http2UpgradeHandler}.
 */
public class TestHttp2UpgradeHandlerHeaderEmitter {

    private static final String INJECTED_NAME = "x-injected";
    private static final String INJECTED_VALUE = "injected";


    @Test
    public void testHeadersStartSetsStreamAsEmitter() throws Exception {
        Http2UpgradeHandler handler = new Http2UpgradeHandler(new Http2Protocol(), null, null);
        HpackDecoder decoder = handler.getHpackDecoder();

        handler.headersStart(3, false);

        Stream stream = handler.getStream(3);
        Assert.assertNotNull(stream);
        Assert.assertSame(stream, decoder.getHeaderEmitter());
        Assert.assertFalse(decoder.getStreamEmitterLock().isLocked());
    }


    @Test
    public void testStreamReplacementSwitchesEmitterToSink() throws Exception {
        Http2UpgradeHandler handler = new Http2UpgradeHandler(new Http2Protocol(), null, null);
        HpackDecoder decoder = handler.getHpackDecoder();

        handler.headersStart(3, false);
        Stream stream = handler.getStream(3);
        Assert.assertSame(stream, decoder.getHeaderEmitter());

        // Container thread closes the stream and replaces it
        stream.replace();

        Assert.assertNull(handler.getStream(3));
        Assert.assertSame(Http2UpgradeHandler.HEADER_SINK, decoder.getHeaderEmitter());
        Assert.assertFalse(decoder.getStreamEmitterLock().isLocked());

        // Headers decoded after the replacement must not reach the replaced stream
        decoder.decode(encode(INJECTED_NAME, INJECTED_VALUE));
        Assert.assertNull(stream.getCoyoteRequest().getMimeHeaders().getHeader(INJECTED_NAME));
    }


    @Test
    public void testStreamReplacementDoesNotReplaceOtherEmitter() throws Exception {
        Http2UpgradeHandler handler = new Http2UpgradeHandler(new Http2Protocol(), null, null);
        HpackDecoder decoder = handler.getHpackDecoder();

        handler.headersStart(3, false);
        Stream stream3 = handler.getStream(3);
        handler.headersStart(5, false);
        Stream stream5 = handler.getStream(5);
        Assert.assertSame(stream5, decoder.getHeaderEmitter());

        // Replacing a stream that is not the current emitter must not change the emitter
        stream3.replace();

        Assert.assertSame(stream5, decoder.getHeaderEmitter());
    }


    @Test
    public void testHeadersStartHoldsStreamEmitterLock() throws Exception {
        final Http2UpgradeHandler handler = new Http2UpgradeHandler(new Http2Protocol(), null, null);
        HpackDecoder decoder = handler.getHpackDecoder();
        ReentrantLock streamEmitterLock = decoder.getStreamEmitterLock();

        final AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread parserThread = new Thread(() -> {
            try {
                handler.headersStart(3, false);
            } catch (Throwable t) {
                failure.set(t);
            }
        });

        /*
         * Simulate a container thread replacing a stream (which holds the stream emitter lock) while the parser thread
         * starts processing a new header block. The parser thread must wait for the lock before it looks up the stream
         * and sets the header emitter.
         */
        streamEmitterLock.lock();
        try {
            parserThread.start();
            int count = 0;
            while (!streamEmitterLock.hasQueuedThread(parserThread) && parserThread.isAlive() && count < 1000) {
                Thread.sleep(10);
                count++;
            }
            Assert.assertTrue(streamEmitterLock.hasQueuedThread(parserThread));
            Assert.assertNull(decoder.getHeaderEmitter());
        } finally {
            streamEmitterLock.unlock();
        }
        parserThread.join(10000);

        Assert.assertFalse(parserThread.isAlive());
        Assert.assertNull(failure.get());
        Assert.assertSame(handler.getStream(3), decoder.getHeaderEmitter());
        Assert.assertFalse(streamEmitterLock.isLocked());
    }


    private static ByteBuffer encode(String name, String value) {
        MimeHeaders headers = new MimeHeaders();
        headers.addValue(name).setString(value);
        ByteBuffer output = ByteBuffer.allocate(512);
        HpackEncoder encoder = new HpackEncoder();
        encoder.encode(headers, output);
        output.flip();
        return output;
    }
}
