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
package org.apache.tomcat.util.net;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.catalina.core.AprLifecycleListener;
import org.apache.coyote.http11.Http11AprProtocol;
import org.apache.tomcat.jni.Library;

/**
 * Tests for the checks performed by the APR/Native connector on the parent directory of a Unix Domain Socket before
 * the socket is created. These checks prevent the time-of-check / time-of-use window between the creation of the
 * socket and the application of the configured permissions from being exploited.
 */
@SuppressWarnings("deprecation")
public class TestAprEndpointUnixDomainSocket {

    private static final String SOCKET_NAME = "tomcat.sock";

    private static boolean aprAvailable = false;

    private Path baseDir;


    @BeforeClass
    public static void initApr() {
        // An instance has to be created before APR/Native can be initialised
        new AprLifecycleListener();
        aprAvailable = AprLifecycleListener.isAprAvailable();
    }


    @Before
    public void setUp() throws IOException {
        Assume.assumeTrue("APR/Native library is not available", aprAvailable);
        Assume.assumeTrue("APR/Native does not support Unix Domain Sockets", Library.APR_HAVE_UNIX);
        Assume.assumeTrue("POSIX file permissions are not supported",
                FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        // Use a short base path as Unix Domain Socket paths are limited in length
        baseDir = Files.createTempDirectory("tomcat-uds-");
    }


    @After
    public void tearDown() throws IOException {
        if (baseDir != null) {
            Files.walkFileTree(baseDir, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.delete(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    Files.delete(dir);
                    return FileVisitResult.CONTINUE;
                }
            });
            baseDir = null;
        }
    }


    /*
     * The parent directory does not exist. It must be created with permissions derived from the socket permissions
     * (execute added where read or write is granted, group and other write removed) before the socket is created.
     */
    @Test
    public void testParentCreatedWithDerivedPermissionsAll() throws Exception {
        doTestParentCreated("rw-rw-rw-", null, "rwxr-xr-x");
    }


    @Test
    public void testParentCreatedWithDerivedPermissionsOwnerOnly() throws Exception {
        doTestParentCreated("rw-------", null, "rwx------");
    }


    @Test
    public void testParentCreatedWithDerivedPermissionsOwnerAndGroup() throws Exception {
        doTestParentCreated("rw-rw----", null, "rwxr-x---");
    }


    @Test
    public void testParentCreatedWithExplicitPermissions() throws Exception {
        doTestParentCreated("rw-rw----", "rwx--x---", "rwx--x---");
    }


    private void doTestParentCreated(String socketPermissions, String parentPermissions, String expectedParent)
            throws Exception {
        Path parent = baseDir.resolve("parent");
        Path socket = parent.resolve(SOCKET_NAME);
        Assert.assertFalse(Files.exists(parent, LinkOption.NOFOLLOW_LINKS));

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions(socketPermissions);
        if (parentPermissions != null) {
            endpoint.setUnixDomainSocketParentPermissions(parentPermissions);
        }

        endpoint.init();
        try {
            Assert.assertTrue(Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS));
            Assert.assertEquals(PosixFilePermissions.fromString(expectedParent),
                    Files.getPosixFilePermissions(parent, LinkOption.NOFOLLOW_LINKS));
            Assert.assertEquals(System.getProperty("user.name"),
                    Files.getOwner(parent, LinkOption.NOFOLLOW_LINKS).getName());
            // APR removes the socket when it is closed so check it before destroy()
            Assert.assertTrue(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
            Assert.assertEquals(PosixFilePermissions.fromString(socketPermissions),
                    Files.getPosixFilePermissions(socket, LinkOption.NOFOLLOW_LINKS));
        } finally {
            endpoint.destroy();
        }
    }


    @Test
    public void testNestedParentsCreated() throws Exception {
        Path grandParent = baseDir.resolve("a");
        Path parent = grandParent.resolve("b");
        Path socket = parent.resolve(SOCKET_NAME);

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-------");

        endpoint.init();
        try {
            Assert.assertTrue(Files.isDirectory(grandParent, LinkOption.NOFOLLOW_LINKS));
            Set<PosixFilePermission> grandParentPermissions =
                    Files.getPosixFilePermissions(grandParent, LinkOption.NOFOLLOW_LINKS);
            Assert.assertFalse(grandParentPermissions.contains(PosixFilePermission.GROUP_WRITE));
            Assert.assertFalse(grandParentPermissions.contains(PosixFilePermission.OTHERS_WRITE));
            Assert.assertEquals(PosixFilePermissions.fromString("rwx------"),
                    Files.getPosixFilePermissions(parent, LinkOption.NOFOLLOW_LINKS));
            Assert.assertTrue(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
            Assert.assertEquals(PosixFilePermissions.fromString("rw-------"),
                    Files.getPosixFilePermissions(socket, LinkOption.NOFOLLOW_LINKS));
        } finally {
            endpoint.destroy();
        }
    }


    /*
     * A pre-existing, world writable parent directory would allow another user to interfere with the socket (e.g.
     * replace it) before the configured permissions are applied. Initialisation must be refused.
     */
    @Test
    public void testExistingParentWorldWritableRejected() throws Exception {
        Path parent = createDirectory("parent", "rwxrwxrwx");
        Path socket = parent.resolve(SOCKET_NAME);

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-------");

        doTestInitRejected(endpoint, parent, socket);

        // The permissions of the existing directory must not have been changed
        Assert.assertEquals(PosixFilePermissions.fromString("rwxrwxrwx"),
                Files.getPosixFilePermissions(parent, LinkOption.NOFOLLOW_LINKS));
    }


    @Test
    public void testExistingParentGroupWritableRejected() throws Exception {
        Path parent = createDirectory("parent", "rwxrwx---");
        Path socket = parent.resolve(SOCKET_NAME);

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketParentPermissions("rwxr-x---");

        doTestInitRejected(endpoint, parent, socket);
    }


    @Test
    public void testExistingParentStricterPermissionsAccepted() throws Exception {
        Path parent = createDirectory("parent", "rwx------");
        Path socket = parent.resolve(SOCKET_NAME);

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-rw-rw-");

        endpoint.init();
        try {
            Assert.assertEquals(PosixFilePermissions.fromString("rwx------"),
                    Files.getPosixFilePermissions(parent, LinkOption.NOFOLLOW_LINKS));
            Assert.assertTrue(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
            Assert.assertEquals(PosixFilePermissions.fromString("rw-rw-rw-"),
                    Files.getPosixFilePermissions(socket, LinkOption.NOFOLLOW_LINKS));
        } finally {
            endpoint.destroy();
        }
    }


    @Test
    public void testParentPermissionChecksSkipped() throws Exception {
        Path parent = createDirectory("parent", "rwxrwxrwx");
        Path socket = parent.resolve(SOCKET_NAME);

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-------");
        endpoint.setUnixDomainSocketParentPermissions("");

        doTestInitAccepted(endpoint, socket);
    }


    @Test
    public void testNoPermissionsConfigured() throws Exception {
        Path parent = createDirectory("parent", "rwxrwxrwx");
        Path socket = parent.resolve(SOCKET_NAME);

        AprEndpoint endpoint = createEndpoint(socket);

        doTestInitAccepted(endpoint, socket);
    }


    /*
     * The parent is a symbolic link to a directory. Links must not be followed else the socket could be created in a
     * location chosen by whoever controls the link.
     */
    @Test
    public void testSymbolicLinkParentRejected() throws Exception {
        Path target = createDirectory("target", "rwx------");
        Path link = baseDir.resolve("link");
        try {
            Files.createSymbolicLink(link, target);
        } catch (UnsupportedOperationException | IOException e) {
            Assume.assumeNoException("Unable to create symbolic link", e);
        }
        Path socket = link.resolve(SOCKET_NAME);

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-------");

        Exception exception = null;
        try {
            try {
                endpoint.init();
            } catch (Exception e) {
                exception = e;
            }
            Assert.assertNotNull("Initialisation should fail when the parent directory is a symbolic link", exception);
            Assert.assertFalse(Files.exists(target.resolve(SOCKET_NAME), LinkOption.NOFOLLOW_LINKS));
        } finally {
            endpoint.destroy();
        }
        Assert.assertTrue(Files.isSymbolicLink(link));
    }


    /*
     * The parent directory exists, has acceptable permissions but is owned by neither the expected owner nor the
     * current user. Another user could interfere with the socket. Initialisation must be refused.
     */
    @Test
    public void testParentOwnerMismatchRejected() throws Exception {
        Path parent = getForeignOwnedDirectory();
        Path socket = createSocketPathIn(parent);

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketParentPermissions("rwxrwxrwx");

        try {
            doTestInitRejected(endpoint, parent, socket);
        } finally {
            Files.deleteIfExists(socket);
        }
    }


    @Test
    public void testParentOwnerUnexpectedOwnerRejected() throws Exception {
        Path parent = getForeignOwnedDirectory();
        Path socket = createSocketPathIn(parent);

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketParentPermissions("rwxrwxrwx");
        endpoint.setUnixDomainSocketParentOwner("tomcat-uds-test-no-such-user");

        try {
            doTestInitRejected(endpoint, parent, socket);
        } finally {
            Files.deleteIfExists(socket);
        }
    }


    @Test
    public void testParentOwnerExpected() throws Exception {
        Path parent = getForeignOwnedDirectory();
        Path socket = createSocketPathIn(parent);

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketParentPermissions("rwxrwxrwx");
        endpoint.setUnixDomainSocketParentOwner(Files.getOwner(parent, LinkOption.NOFOLLOW_LINKS).getName());

        try {
            doTestInitAccepted(endpoint, socket);
        } finally {
            Files.deleteIfExists(socket);
        }
    }


    @Test
    public void testParentOwnerCheckSkipped() throws Exception {
        Path parent = getForeignOwnedDirectory();
        Path socket = createSocketPathIn(parent);

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketParentPermissions("rwxrwxrwx");
        endpoint.setUnixDomainSocketParentOwner("");

        try {
            doTestInitAccepted(endpoint, socket);
        } finally {
            Files.deleteIfExists(socket);
        }
    }


    private static AprEndpoint createEndpoint(Path socket) {
        AprEndpoint endpoint = new AprEndpoint();
        // The protocol configures the handler the endpoint requires for unbind()
        new Http11AprProtocol(endpoint);
        endpoint.setUnixDomainSocketPath(socket.toAbsolutePath().toString());
        return endpoint;
    }


    private Path createDirectory(String name, String permissions) throws IOException {
        Path dir = baseDir.resolve(name);
        Files.createDirectory(dir);
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString(permissions));
        return dir;
    }


    private static void doTestInitAccepted(AprEndpoint endpoint, Path socket) throws Exception {
        endpoint.init();
        try {
            Assert.assertTrue(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
        } finally {
            endpoint.destroy();
        }
    }


    private static void doTestInitRejected(AprEndpoint endpoint, Path parent, Path socket) throws Exception {
        IllegalStateException ise = null;
        try {
            try {
                endpoint.init();
            } catch (IllegalStateException e) {
                ise = e;
            }
            Assert.assertNotNull("Initialisation should fail for the parent directory [" + parent + "]", ise);
            Assert.assertTrue(ise.getMessage(), ise.getMessage().contains(parent.toAbsolutePath().toString()));
            // The socket must not have been created
            Assert.assertFalse(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
        } finally {
            endpoint.destroy();
        }
    }


    /*
     * Use the system temporary directory as an existing directory that is owned by a user other than the current
     * user (typically root).
     */
    private static Path getForeignOwnedDirectory() throws IOException {
        Path dir = Paths.get(System.getProperty("java.io.tmpdir")).toAbsolutePath().normalize();
        Assume.assumeTrue(Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS));
        String owner = Files.getOwner(dir, LinkOption.NOFOLLOW_LINKS).getName();
        Assume.assumeFalse("The temporary directory is owned by the current user",
                owner.equals(System.getProperty("user.name")));
        return dir;
    }


    private static Path createSocketPathIn(Path dir) throws IOException {
        File file = File.createTempFile("tomcat-uds-", ".sock", dir.toFile());
        // Need to delete the file to make way for the actual socket
        Assert.assertTrue(file.delete());
        return file.toPath();
    }
}
