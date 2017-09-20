/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2017 Zimbra, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */

package com.zimbra.qa.unittest;

import com.zimbra.common.account.Key;
import com.zimbra.common.util.Pair;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AttributeManager;
import com.zimbra.cs.account.Config;
import com.zimbra.cs.account.Entry;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.Server;
import com.zimbra.cs.account.UnitTestAccount;
import com.zimbra.cs.account.UnitTestServer;
import com.zimbra.cs.account.ldap.LdapProv;
import com.zimbra.cs.account.ldap.LdapProvisioning;
import com.zimbra.cs.imap.ImapLoadBalancingMechanism;
import com.zimbra.cs.nginx.NginxLookupExtension;

import junit.framework.TestCase;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.easymock.EasyMock;
import org.powermock.api.easymock.PowerMock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;

import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;


@RunWith(PowerMockRunner.class)
@PrepareForTest({Account.class, AttributeManager.class, Config.class, Entry.class, HttpServletRequest.class,
        LdapProv.class, LdapProvisioning.class,
        NginxLookupExtension.NginxLookupHandler.class,
        NginxLookupExtension.NginxLookupRequest.class,
        Provisioning.class, Server.class, UnitTestServer.class, UnitTestAccount.class})
public class NginxLookupExtensionTest extends TestCase {

    private static final String USER = "testnginxlookupextension-user1";

    private static String DEFAULT_DOMAIN = "NginxLookupExtensionTest.local";

    private static String QUSER = USER + "@" +DEFAULT_DOMAIN;

    @Mock HttpServletRequest mockServletReq;

    NginxLookupExtension.NginxLookupHandler handler;

    Config config;

    @Before
    public void setUp() throws Exception {
        config = Whitebox.newInstance(Config.class);
        Whitebox.setInternalState(config, "mAttrs", new HashMap<>());
        mockServletReq = PowerMock.createMock(HttpServletRequest.class);
        handler = Whitebox.newInstance(NginxLookupExtension.NginxLookupHandler.class);
        PowerMock.resetAll();
    }

    @Test
    public void testLookupUpstreamImapServerNoAccount() throws Exception {
        LdapProvisioning mockProvisioning = PowerMock.createMock(LdapProvisioning.class);
        EasyMock.expect(mockProvisioning.get(Key.AccountBy.name, QUSER)).andReturn(null);
        EasyMock.expect(mockProvisioning.getConfig()).andReturn(config).anyTimes();

        Provisioning.setInstance(mockProvisioning);
        PowerMock.mockStatic(Provisioning.class);

        handler = Whitebox.newInstance(NginxLookupExtension.NginxLookupHandler.class);
        Whitebox.setInternalState(handler, "prov", mockProvisioning);

        PowerMock.mockStatic(ImapLoadBalancingMechanism.class);
        PowerMock.suppress(PowerMock.constructor(ImapLoadBalancingMechanism.class));

        AttributeManager mockAttributeManager = PowerMock.createMock(AttributeManager.class);
        EasyMock.expect(mockAttributeManager.isEphemeral("zimbraImapLoadBalancingAlgorithm")).andReturn(false);
        EasyMock.expect(mockAttributeManager.getAttributeInfo("zimbraImapLoadBalancingAlgorithm")).andReturn(null);

        Whitebox.setInternalState(config, "mAttrMgr", mockAttributeManager);

        NginxLookupExtension.NginxLookupRequest request = Whitebox.newInstance(NginxLookupExtension.NginxLookupRequest.class);
        Whitebox.setInternalState(request, "user", QUSER);
        Whitebox.setInternalState(request, "httpReq", mockServletReq);

        PowerMock.replayAll();

        Pair<Server, Boolean> server = Whitebox.invokeMethod(handler, "lookupUpstreamImapServer", request);
        assertEquals("Server objects should be null", null, server);
        PowerMock.verifyAll();
    }

    @Test
    public void testLookupUpstreamImapServerNoUpstreamServers() throws Exception {
        Account account = Whitebox.newInstance(UnitTestAccount.class);

        LdapProvisioning mockProvisioning = PowerMock.createMock(LdapProvisioning.class);
        EasyMock.expect(mockProvisioning.get(Key.AccountBy.name, QUSER)).andReturn(account);
        EasyMock.expect(mockProvisioning.getConfig()).andReturn(config).anyTimes();
        Whitebox.setInternalState(handler, "prov", mockProvisioning);

        Provisioning.setInstance(mockProvisioning);
        PowerMock.mockStatic(Provisioning.class);

        PowerMockito.suppress(PowerMockito.constructor(Server.class));
        /*ImapLoadBalancingMechanism mockLBMech = PowerMock.createMock(ImapLoadBalancingMechanism.class);
        PowerMockito.stub(PowerMockito.method(ImapLoadBalancingMechanism.class, "newInstance")).toReturn(mockLBMech);
        EasyMock.expect(ImapLoadBalancingMechanism.newInstance()).andStubReturn(mockLBMech);
        */
        String[] servers = {};

        Server testServer = Whitebox.newInstance(UnitTestServer.class);
        Whitebox.setInternalState(testServer, "reverseProxyUpstreamImapServers", servers);
        Whitebox.setInternalState(testServer, "hostname", DEFAULT_DOMAIN);
        Whitebox.setInternalState(account, "server", testServer);
        EasyMock.expect(mockProvisioning.getServerByServiceHostname(DEFAULT_DOMAIN)).andReturn(testServer);

        AttributeManager mockAttributeManager = PowerMock.createMock(AttributeManager.class);
        EasyMock.expect(mockAttributeManager.isEphemeral("zimbraImapLoadBalancingAlgorithm")).andReturn(false).anyTimes();
        EasyMock.expect(mockAttributeManager.getAttributeInfo("zimbraImapLoadBalancingAlgorithm")).andReturn(null).anyTimes();
        Whitebox.setInternalState(config, "mAttrMgr", mockAttributeManager);

        NginxLookupExtension.NginxLookupRequest request = Whitebox.newInstance(NginxLookupExtension.NginxLookupRequest.class);
        Whitebox.setInternalState(request, "user", QUSER);
        Whitebox.setInternalState(request, "httpReq", mockServletReq);
        EasyMock.expect(mockServletReq.getHeader("Client-IP")).andReturn("127.0.0.1").anyTimes();

        PowerMock.replayAll();

        Pair<Server, Boolean> server = Whitebox.invokeMethod(handler, "lookupUpstreamImapServer", request);
        assertEquals("Server objects should be the same", testServer, server.getFirst());

        PowerMock.verifyAll();
    }

    @Test
    public void testLookupUpstreamImapServerUpstreamServers() throws Exception {
        String[] servers = {DEFAULT_DOMAIN};
        Server testServer = Whitebox.newInstance(UnitTestServer.class);
        LdapProvisioning mockProvisioning = PowerMock.createMock(LdapProvisioning.class);
        UnitTestAccount account = Whitebox.newInstance(UnitTestAccount.class);
        EasyMock.expect(mockProvisioning.get(Key.AccountBy.name, QUSER)).andReturn(account);
        EasyMock.expect(mockProvisioning.getServerByServiceHostname(DEFAULT_DOMAIN)).andReturn(testServer);
        EasyMock.expect(mockProvisioning.getConfig()).andReturn(config).anyTimes();

        Provisioning.setInstance(mockProvisioning);
        PowerMock.mockStatic(Provisioning.class);

        Whitebox.setInternalState(testServer, "reverseProxyUpstreamImapServers", servers);
        Whitebox.setInternalState(testServer, "hostname", DEFAULT_DOMAIN);
        Whitebox.setInternalState(account, "server", testServer);

        NginxLookupExtension.NginxLookupRequest mockRequest = Whitebox.newInstance(NginxLookupExtension.NginxLookupRequest.class);
        Whitebox.setInternalState(mockRequest, "user", QUSER);
        Whitebox.setInternalState(mockRequest, "httpReq", mockServletReq);
        NginxLookupExtension.NginxLookupHandler mockHandler = Whitebox.newInstance(NginxLookupExtension.NginxLookupHandler.class);
        Whitebox.setInternalState(mockHandler, "prov", mockProvisioning);

        EasyMock.expect(mockServletReq.getHeader("Client-IP")).andReturn("127.0.0.1").anyTimes();

        AttributeManager mockAttributeManager = PowerMock.createMock(AttributeManager.class);
        EasyMock.expect(mockAttributeManager.isEphemeral("zimbraImapLoadBalancingAlgorithm")).andReturn(false).anyTimes();
        EasyMock.expect(mockAttributeManager.getAttributeInfo("zimbraImapLoadBalancingAlgorithm")).andReturn(null).anyTimes();
        Whitebox.setInternalState(config, "mAttrMgr", mockAttributeManager);

        PowerMock.replayAll();

        Pair<Server, Boolean> server = Whitebox.invokeMethod(mockHandler, "lookupUpstreamImapServer", mockRequest);
        assertEquals("Server objects should be the same", testServer, server.getFirst());

        PowerMock.verifyAll();
    }

    @Test
    public void testGetUpstreamIMAPPort() throws Exception {
        NginxLookupExtension.NginxLookupHandler mockHandler = Whitebox.newInstance(NginxLookupExtension.NginxLookupHandler.class);
        Server mockServer = Whitebox.newInstance(UnitTestServer.class);

      // internal imap
        String portString = Whitebox.invokeMethod(mockHandler, "getUpstreamIMAPPort", mockServer, "imap", false);
        assertEquals("imap-internal", portString);
        portString = Whitebox.invokeMethod(mockHandler, "getUpstreamIMAPPort", mockServer, "imaps", false);
        assertEquals("imaps-internal", portString);

        // remote imap
        portString = Whitebox.invokeMethod(mockHandler, "getUpstreamIMAPPort", mockServer, "imap", true);
        assertEquals("imap-remote", portString);
        portString = Whitebox.invokeMethod(mockHandler, "getUpstreamIMAPPort", mockServer, "imaps", true);
        assertEquals("imaps-remote", portString);
    }

}
