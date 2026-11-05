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
package org.apache.catalina.tribes.membership.cloud;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.Assert;
import org.junit.Test;

/*
 * The service account token used to authenticate against the Kubernetes API
 * must never be written to the logs or to exception messages.
 */
public class TestTokenStreamProvider {

    private static final String TOKEN = "SECRET-SERVICE-ACCOUNT-TOKEN-0123456789";

    // Unknown protocol so the connection attempt fails without any network I/O
    private static final String URL = "unknown://kubernetes.invalid/api/v1/namespaces/default/pods";


    @Test
    public void testTokenNotInExceptionMessage() throws Exception {
        TokenStreamProvider provider = new TokenStreamProvider(TOKEN, null);

        IOException ioe = null;
        try {
            provider.openStream(URL, new HashMap<String,String>(), 1000, 1000);
        } catch (IOException e) {
            ioe = e;
        }

        Assert.assertNotNull(ioe);
        Assert.assertNotNull(ioe.getMessage());
        Assert.assertTrue(ioe.getMessage(), ioe.getMessage().contains(URL));
        Throwable t = ioe;
        while (t != null) {
            String msg = t.getMessage();
            if (msg != null) {
                Assert.assertFalse(msg, msg.contains(TOKEN));
            }
            t = t.getCause();
        }
    }


    @Test
    public void testTokenNotInDebugLog() throws Exception {
        Logger logger = Logger.getLogger(AbstractStreamProvider.class.getName());
        Level originalLevel = logger.getLevel();
        CapturingHandler handler = new CapturingHandler();
        logger.addHandler(handler);
        logger.setLevel(Level.ALL);
        try {
            TokenStreamProvider provider = new TokenStreamProvider(TOKEN, null);
            try {
                provider.openStream(URL, new HashMap<String,String>(), 1000, 1000);
                Assert.fail("Connection to [" + URL + "] should have failed");
            } catch (IOException expected) {
                // Expected
            }
        } finally {
            logger.setLevel(originalLevel);
            logger.removeHandler(handler);
        }

        // Make sure the connection debug message was actually logged
        boolean connectionLogged = false;
        for (String msg : handler.messages) {
            if (msg.contains(URL)) {
                connectionLogged = true;
            }
            Assert.assertFalse(msg, msg.contains(TOKEN));
        }
        Assert.assertTrue(connectionLogged);
    }


    private static class CapturingHandler extends Handler {

        private final List<String> messages = new CopyOnWriteArrayList<>();

        @Override
        public void publish(LogRecord record) {
            String msg = record.getMessage();
            if (msg != null) {
                messages.add(msg);
            }
        }

        @Override
        public void flush() {
            // NO-OP
        }

        @Override
        public void close() throws SecurityException {
            // NO-OP
        }
    }
}
