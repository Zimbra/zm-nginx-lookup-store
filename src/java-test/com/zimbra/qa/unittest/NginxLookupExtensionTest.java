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

import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;

import org.easymock.EasyMock;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.api.easymock.PowerMock;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;

import com.zimbra.common.account.Key;
import com.zimbra.common.service.ServiceException;
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
import com.zimbra.cs.nginx.NginxLookupExtension.NginxLookupHandler;
import com.zimbra.cs.nginx.NginxLookupExtension.NginxLookupHandler.ConnConfig;
import com.zimbra.cs.nginx.NginxLookupExtension.NginxLookupRequest;

import junit.framework.TestCase;


@RunWith(PowerMockRunner.class)
@PrepareForTest({Account.class, AttributeManager.class, Config.class, Entry.class, HttpServletRequest.class,
        LdapProv.class, LdapProvisioning.class,
        NginxLookupHandler.class,
        NginxLookupRequest.class,
        Provisioning.class, Server.class, UnitTestServer.class, UnitTestAccount.class})
public class NginxLookupExtensionTest extends TestCase {

    private static final String USER = "testnginxlookupextension-user1";

    private static String DEFAULT_DOMAIN = "NginxLookupExtensionTest.local";

    private static String QUSER = USER + "@" +DEFAULT_DOMAIN;

    @Mock HttpServletRequest mockServletReq;

    NginxLookupHandler handler;

    Config config;

    @Override
    @Before
    public void setUp() throws Exception {
        config = Whitebox.newInstance(Config.class);
        Whitebox.setInternalState(config, "mAttrs", new HashMap<>());
        mockServletReq = PowerMock.createMock(HttpServletRequest.class);
        handler = Whitebox.newInstance(NginxLookupHandler.class);
        PowerMock.resetAll();
    }

    private NginxLookupRequest makeMockNginxLookupRequest() {
        NginxLookupRequest mockRequest = Whitebox.newInstance(NginxLookupRequest.class);
        Whitebox.setInternalState(mockRequest, "user", QUSER);
        Whitebox.setInternalState(mockRequest, "httpReq", mockServletReq);
        Whitebox.setInternalState(mockRequest, "proto", "imaps");
        return mockRequest;
    }

    private LdapProvisioning makeMockProvisioning(Account acct, Server server) throws ServiceException {
        LdapProvisioning mockProvisioning = PowerMock.createMock(LdapProvisioning.class);
        EasyMock.expect(mockProvisioning.get(Key.AccountBy.name, QUSER)).andReturn(acct);
        if (server != null) {
            EasyMock.expect(mockProvisioning.getServerByServiceHostname(DEFAULT_DOMAIN)).andReturn(server);
        }
        EasyMock.expect(mockProvisioning.getConfig()).andReturn(config).anyTimes();
        return mockProvisioning;
    }

    private Server makeMockServer(String[] servers) {
        Server testServer = Whitebox.newInstance(UnitTestServer.class);
        Whitebox.setInternalState(testServer, "reverseProxyUpstreamImapServers", servers);
        Whitebox.setInternalState(testServer, "hostname", DEFAULT_DOMAIN);
        return testServer;
    }

    private Account makeMockAccount(Server server, String acctId) {
        UnitTestAccount account = Whitebox.newInstance(UnitTestAccount.class);
        Whitebox.setInternalState(account, "server", server);
        Whitebox.setInternalState(account, "id", acctId);
        return account;
    }

    @Test
    public void testChooseReverseProxyUpstreamImapServerNoAccount() throws Exception {
        LdapProvisioning mockProvisioning = makeMockProvisioning((Account)null, (Server)null);

        Provisioning.setInstance(mockProvisioning);
        PowerMock.mockStatic(Provisioning.class);

        handler = Whitebox.newInstance(NginxLookupHandler.class);
        Whitebox.setInternalState(handler, "prov", mockProvisioning);

        PowerMock.mockStatic(ImapLoadBalancingMechanism.class);
        PowerMock.suppress(PowerMock.constructor(ImapLoadBalancingMechanism.class));

        AttributeManager mockAttributeManager = PowerMock.createMock(AttributeManager.class);
        Whitebox.setInternalState(config, "mAttrMgr", mockAttributeManager);

        NginxLookupRequest mockRequest = makeMockNginxLookupRequest();
        PowerMock.replayAll();

        ConnConfig conn = new ConnConfig();
        Whitebox.invokeMethod(handler, "chooseUsingReverseProxyUpstreamImapServer", mockRequest, conn);
        assertNull("conn.host after chooseUsingReverseProxyUpstreamImapServer", conn.host);
        PowerMock.verifyAll();
    }

    @Test
    public void testChooseReverseProxyUpstreamImapServerNoUpstreamServers() throws Exception {
        String acctId = "1234-5678";
        String[] servers = {};
        Server testServer = makeMockServer(servers);
        Account account = makeMockAccount(testServer, acctId);
        LdapProvisioning mockProvisioning = makeMockProvisioning(account, (Server)null);
        Whitebox.setInternalState(handler, "prov", mockProvisioning);

        Provisioning.setInstance(mockProvisioning);
        PowerMock.mockStatic(Provisioning.class);

        PowerMockito.suppress(PowerMockito.constructor(Server.class));

        AttributeManager mockAttributeManager = PowerMock.createMock(AttributeManager.class);
        EasyMock.expect(mockAttributeManager.isEphemeral("zimbraImapLoadBalancingAlgorithm")).andReturn(false).anyTimes();
        EasyMock.expect(mockAttributeManager.getAttributeInfo("zimbraImapLoadBalancingAlgorithm")).andReturn(null).anyTimes();
        Whitebox.setInternalState(config, "mAttrMgr", mockAttributeManager);

        NginxLookupRequest mockRequest = makeMockNginxLookupRequest();
        EasyMock.expect(mockServletReq.getHeader("Client-IP")).andReturn("127.0.0.1").anyTimes();

        PowerMock.replayAll();

        ConnConfig conn = new ConnConfig();
        Whitebox.invokeMethod(handler, "chooseUsingReverseProxyUpstreamImapServer", mockRequest, conn);
        assertNull("conn.host after chooseUsingReverseProxyUpstreamImapServer", conn.host);

        PowerMock.verifyAll();
    }

    @Test
    public void testChooseReverseProxyUpstreamImapServerWithConfiguredServers() throws Exception {
        String[] servers = {DEFAULT_DOMAIN};
        String acctId = "1234-5678";
        Server testServer = makeMockServer(servers);
        Account account = makeMockAccount(testServer, acctId);
        LdapProvisioning mockProvisioning = makeMockProvisioning(account, testServer);

        Provisioning.setInstance(mockProvisioning);
        PowerMock.mockStatic(Provisioning.class);

        NginxLookupRequest mockRequest = makeMockNginxLookupRequest();
        Whitebox.setInternalState(handler, "prov", mockProvisioning);

        EasyMock.expect(mockServletReq.getHeader("Client-IP")).andReturn("127.0.0.1").anyTimes();

        AttributeManager mockAttributeManager = PowerMock.createMock(AttributeManager.class);
        EasyMock.expect(mockAttributeManager.isEphemeral("zimbraImapLoadBalancingAlgorithm")).andReturn(false).anyTimes();
        EasyMock.expect(mockAttributeManager.getAttributeInfo("zimbraImapLoadBalancingAlgorithm")).andReturn(null).anyTimes();
        Whitebox.setInternalState(config, "mAttrMgr", mockAttributeManager);

        PowerMock.replayAll();

        ConnConfig conn = new ConnConfig();
        Whitebox.invokeMethod(handler, "chooseUsingReverseProxyUpstreamImapServer", mockRequest, conn);
        assertEquals("conn.host after chooseUsingReverseProxyUpstreamImapServer",
                testServer.getServiceHostname(), conn.host);

        PowerMock.verifyAll();
    }

    @Test
    public void testGetUpstreamIMAPPort() throws Exception {
        NginxLookupHandler mockHandler = Whitebox.newInstance(NginxLookupHandler.class);
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
