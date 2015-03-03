/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2010, 2011, 2012, 2013, 2014 Zimbra, Inc.
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

package com.zimbra.cs.nginx;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import junit.framework.Assert;

import org.apache.commons.lang.StringUtils;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.zimbra.common.account.Key;
import com.zimbra.common.account.Key.AlwaysOnClusterBy;
import com.zimbra.common.account.ProvisioningConstants;
import com.zimbra.common.localconfig.DebugConfig;
import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AlwaysOnCluster;
import com.zimbra.cs.account.Domain;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.Provisioning.MailMode;
import com.zimbra.cs.account.Server;
import com.zimbra.cs.account.ldap.LdapProv;
import com.zimbra.cs.account.ldap.LdapProvisioning;
import com.zimbra.cs.nginx.NginxLookupExtension.NginxLookupRequest;
import com.zimbra.cs.nginx.NginxLookupExtension.NginxLookupResponse;
import com.zimbra.cs.util.Zimbra;

public class NginxLookupHandlerTest {

    private static final String USER = "user1";
    private static final String DEFAULT_DOMAIN = "phoebe.mbp";
    private static final String QUSER = USER + "@" + DEFAULT_DOMAIN;
    private static final String PASSWORD = "test123";
    private static final String LOCALHOST = "localhost";
    private static final String POP3_PORT     = "7110";
    private static final String POP3_SSL_PORT = "7995";
    private static final String IMAP_PORT     = "7143";
    private static final String IMAP_SSL_PORT = "7993";
    private static final String HTTP_PORT     = "7070";
    private LdapProv prov;
    private NginxLookupHandler handler;
    private AlwaysOnCluster cluster; // if this gets assigned, delete in after-test cleanup

    private enum AuthMethod {
        plain,
        other,
        zimbraId,
        gssapi
    }

    private enum AuthProtocol {
        pop3,
        pop3ssl,
        imap,
        imapssl,
        http
    }

    public NginxLookupHandlerTest() throws Exception {
        System.setProperty("log4j.configuration", "log4j-test.properties");
    }

    boolean isServiceLocatorAvailableForTests() {
        try {
            handler.serviceLocator.ping();
            return true;
        } catch(IOException e) {
            return false;
        }
    }

    boolean isLdapServerAvailableForTests() {
        try {
            LDAPConnection conn = new LDAPConnection();
            LDAPConnectionOptions opts = new LDAPConnectionOptions();
            opts.setConnectTimeoutMillis(250);
            conn.setConnectionOptions(opts);
            conn.connect("127.0.0.1", 389);
            conn.close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Before
    public void before() throws Exception {
        Assume.assumeTrue(isLdapServerAvailableForTests());
        Zimbra.startupMinimal();
        prov = LdapProvisioning.getInst();
        handler = new NginxLookupHandler(prov);
        prov.getConfig().setDefaultDomainName(DEFAULT_DOMAIN);

        Assume.assumeTrue(isServiceLocatorAvailableForTests());

        // All the tests by default don't depend on DNS lookups
        Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put(Provisioning.A_zimbraReverseProxyDnsLookupInServerEnabled, ProvisioningConstants.FALSE);
        prov.getLocalServer().modify(attrs);
        DebugConfig.setNginxLookupServerReassignOnHealthCheckEnabled(false);
    }

    @After
    public void after() throws Exception {
        DebugConfig.setNginxLookupServerReassignOnHealthCheckEnabled(true);
        if (prov != null) {
            Account account = prov.getAccountByName(QUSER);
            if (account != null) {
                prov.deleteAccount(account.getId());
            }
            if (cluster != null) {
                prov.deleteAlwaysOnCluster(cluster.getId());
                cluster = null;
            }
        }
    }

    void assertHeader(NginxLookupResponse res, String header, String expectedValue) {
        Assert.assertEquals(StringUtils.lowerCase(expectedValue), StringUtils.lowerCase(res.httpResp.getHeader(header)));
    }

    void assertAuthStatusOK(NginxLookupResponse res) {
        assertHeader(res, NginxLookupHandler.AUTH_STATUS, "OK");
    }

    void assertAuthUser(NginxLookupResponse res, String expected) {
        assertHeader(res, NginxLookupHandler.AUTH_USER, expected);
    }

    void assertAuthServer(NginxLookupResponse res, String expected) {
        assertHeader(res, NginxLookupHandler.AUTH_SERVER, expected);
    }

    void assertAuthPort(NginxLookupResponse res, String expected) {
        assertHeader(res, NginxLookupHandler.AUTH_PORT, expected);
    }

    void assertBasic(NginxLookupResponse res, String expectedUser, String expectedServer, String expectedPort) {
        assertAuthStatusOK(res);
        assertAuthUser(res, expectedUser);
        assertAuthServer(res, expectedServer);
        assertAuthPort(res, expectedPort);
    }

    private Account createAccount(String localpart, String domainName) throws ServiceException {
        getOrCreateDomain(domainName);
        Account acct = prov.getAccountByName(localpart+"@"+domainName);
        if (acct != null) {
            deleteAccount(acct);
        }
        acct = prov.createAccount(localpart+"@"+domainName, PASSWORD, new HashMap<String, Object>());
        return acct;
    }

    private void deleteAccount(Account acct) throws ServiceException {
        prov.deleteAccount(acct.getId());
    }

    private Domain getDomain(String name) throws ServiceException {
        return prov.get(Key.DomainBy.name, name);
    }

    private Domain getOrCreateDomain(String domainName) throws ServiceException {
        Domain domain = getDomain(domainName);
        if (domain == null) {
            domain = createDomain(domainName);
        }
        return domain;
    }

    private Domain createDomain(String domainName) throws ServiceException {
        return prov.createDomain(domainName, new HashMap<String, Object>());
    }

    private void deleteDomain(Domain domain) throws ServiceException {
        prov.deleteDomain(domain.getId());
    }

    private Server createServer(String serverName) throws ServiceException {
        Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put(Provisioning.A_zimbraMailMode, MailMode.http.toString());
        attrs.put(Provisioning.A_zimbraSmtpPort, "7025");
        attrs.put(Provisioning.A_zimbraLowestSupportedAuthVersion, "1");
        return prov.createServer(serverName, attrs);
    }

    private Server getServer(String name) throws ServiceException {
        return prov.get(Key.ServerBy.name, name);
    }

    private AlwaysOnCluster getOrCreateCluster(String clusterName) throws ServiceException {
        AlwaysOnCluster cluster = prov.get(AlwaysOnClusterBy.name, clusterName);
        if (cluster == null) {
            cluster = prov.createAlwaysOnCluster(clusterName, new HashMap<>());
        }
        return cluster;
    }

    private Server getOrCreateServer(String serverName) throws ServiceException {
        Server server = getServer(serverName);
        if (server == null) {
            server = createServer(serverName);
        }
        return server;
    }

    private void setupExternalRoute(Account acct, Boolean useExternalRoute,
            String pop3Port, String pop3sslPort, String imapPort, String imapsslPort) throws Exception {
        Map<String,Object> attrs = new HashMap<String,Object>();
        if (useExternalRoute != null)
            acct.setReverseProxyUseExternalRoute(useExternalRoute, attrs);
        acct.setExternalPop3PortAsString(pop3Port, attrs);
        acct.setExternalPop3SSLPortAsString(pop3sslPort, attrs);
        acct.setExternalImapPortAsString(imapPort, attrs);
        acct.setExternalImapSSLPortAsString(imapsslPort, attrs);
        acct.setExternalPop3Hostname(LOCALHOST, attrs);
        acct.setExternalPop3SSLHostname(LOCALHOST, attrs);
        acct.setExternalImapHostname(LOCALHOST, attrs);
        acct.setExternalImapSSLHostname(LOCALHOST, attrs);
        prov.modifyAttrs(acct, attrs);
    }

    private void setupExternalRoute(Domain domain, Boolean useExternalRoute, Boolean useExternalRouteIfAccountNotExist,
            String pop3Port, String pop3sslPort, String imapPort, String imapsslPort) throws Exception {
        Map<String,Object> attrs = new HashMap<String,Object>();
        if (useExternalRoute != null)
            domain.setReverseProxyUseExternalRoute(useExternalRoute, attrs);
        if (useExternalRouteIfAccountNotExist != null)
            domain.setReverseProxyUseExternalRouteIfAccountNotExist(useExternalRouteIfAccountNotExist, attrs);
        domain.setExternalPop3PortAsString(pop3Port, attrs);
        domain.setExternalPop3SSLPortAsString(pop3sslPort, attrs);
        domain.setExternalImapPortAsString(imapPort, attrs);
        domain.setExternalImapSSLPortAsString(imapsslPort, attrs);
        domain.setExternalPop3Hostname(LOCALHOST, attrs);
        domain.setExternalPop3SSLHostname(LOCALHOST, attrs);
        domain.setExternalImapHostname(LOCALHOST, attrs);
        domain.setExternalImapSSLHostname(LOCALHOST, attrs);
        prov.modifyAttrs(domain, attrs);
    }

    private static String baseDomainName() {
        return NginxLookupHandlerTest.class.getName().toLowerCase();
    }

    private static String getDomainName(String domainName) {
        return domainName + "." + baseDomainName();
    }

    private InetAddress getTestServer() throws UnknownHostException {
        String addr = System.getenv("ZIMBRA_HOSTNAME");
        if (addr != null) {
            return InetAddress.getByName(addr);
        }
        return InetAddress.getLocalHost();
    }

    @Test
    public void imap() throws Exception {
        createAccount(USER, DEFAULT_DOMAIN);
        NginxLookupRequest req = new NginxLookupRequest(USER, PASSWORD, AuthMethod.plain.name(), AuthProtocol.imap.name());
        NginxLookupResponse res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, QUSER, getTestServer().getHostName(), IMAP_PORT);
    }

    @Test
    public void imapForAccountWithoutServerAssigned() throws Exception {
        final String HOSTNAME = getTestServer().getHostName();
        final String HOSTADDR = "1.2.3.4";
        final int PORT = 1000 + new Random().nextInt(100);
        final String serviceID = NginxLookupHandler.getServiceIDForProto(AuthProtocol.imap.name());

        MockServiceLocator serviceLocator = new MockServiceLocator();
        serviceLocator.add(serviceID, HOSTNAME, HOSTADDR, PORT);
        handler.setServiceLocator(serviceLocator);

        Account account = createAccount(USER, DEFAULT_DOMAIN);
        account.unsetMailHost();
        NginxLookupRequest req = new NginxLookupRequest(USER, PASSWORD, AuthMethod.plain.name(), AuthProtocol.imap.name());
        NginxLookupResponse res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, QUSER, HOSTNAME, "" + PORT);
    }

    /** When 2 IMAP upstreams exist, test whether one can fail and the other gets assigned the account */
    @Test
    public void imapFailover() throws Exception {
        final String HOSTNAME_A = "serverA.acme.org";
        final String HOSTNAME_B = "serverB.acme.org";
        final String HOSTADDR_A = "1.2.3.4";
        final String HOSTADDR_B = "2.3.4.5";
        final int PORT_A = 1000 + new Random().nextInt(100);
        final int PORT_B = PORT_A + 1;
        final String serviceID = NginxLookupHandler.getServiceIDForProto(AuthProtocol.imap.name());

        cluster = getOrCreateCluster(getClass().getName());

        Server server_A = getOrCreateServer(HOSTNAME_A);
        server_A.addServiceEnabled(Provisioning.SERVICE_MAILBOX);
        server_A.setImapBindPort(PORT_A);
        server_A.setAlwaysOnClusterId(cluster.getId());

        Server server_B = getOrCreateServer(HOSTNAME_B);
        server_B.addServiceEnabled(Provisioning.SERVICE_MAILBOX);
        server_B.setImapBindPort(PORT_B);
        server_A.setAlwaysOnClusterId(cluster.getId());

        MockServiceLocator serviceLocator = new MockServiceLocator();
        serviceLocator.add(serviceID, HOSTNAME_A, HOSTADDR_A, PORT_A);
        serviceLocator.add(serviceID, HOSTNAME_B, HOSTADDR_B, PORT_B);
        handler.setServiceLocator(serviceLocator);

        Account account = createAccount(USER, DEFAULT_DOMAIN);
        account.setMailHost(server_A.getName());

        // Server reassign is disabled for all tests by default, except this one.
        DebugConfig.setNginxLookupServerReassignOnHealthCheckEnabled(true);

        // Perform 1st lookup. Sanity check - expect account to be assigned to its original server A
        NginxLookupRequest req = new NginxLookupRequest(USER, PASSWORD, AuthMethod.plain.name(), AuthProtocol.imap.name());
        NginxLookupResponse res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, QUSER, HOSTNAME_A, "" + PORT_A);

        // Kill server A (set as unhealthy), from the Service Locator's perspective
        serviceLocator.setHealthy(serviceID, HOSTNAME_A, false);

        // Perform 2nd lookup. Expect the account to get reassigned to server B
        req = new NginxLookupRequest(USER, PASSWORD, AuthMethod.plain.name(), AuthProtocol.imap.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, QUSER, HOSTNAME_B, "" + PORT_B);
    }

    @Test
    public void imapssl() throws Exception {
        createAccount(USER, DEFAULT_DOMAIN);
        NginxLookupRequest req = new NginxLookupRequest(USER, PASSWORD, AuthMethod.plain.name(), AuthProtocol.imapssl.name());
        NginxLookupResponse res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, QUSER, getTestServer().getHostName(), IMAP_SSL_PORT);
    }

    @Test
    public void pop3() throws Exception {
        createAccount(USER, DEFAULT_DOMAIN);
        NginxLookupRequest req = new NginxLookupRequest(USER, PASSWORD, AuthMethod.plain.name(), AuthProtocol.pop3.name());
        NginxLookupResponse res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, QUSER, getTestServer().getHostName(), POP3_PORT);
    }

    @Test
    public void pop3ssl() throws Exception {
        createAccount(USER, DEFAULT_DOMAIN);
        NginxLookupRequest req = new NginxLookupRequest(USER, PASSWORD, AuthMethod.plain.name(), AuthProtocol.pop3ssl.name());
        NginxLookupResponse res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, QUSER, getTestServer().getHostName(), POP3_SSL_PORT);
    }

    @Test
    public void http() throws Exception {
        createAccount(USER, DEFAULT_DOMAIN);
        NginxLookupRequest req = new NginxLookupRequest(USER, PASSWORD, AuthMethod.plain.name(), AuthProtocol.http.name());
        NginxLookupResponse res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, QUSER, getTestServer().getHostName(), HTTP_PORT);
    }

    @Test
    public void externalRouteOnAccountUseRouteOnAccount() throws Exception {
        String user = "user";
        String domainName = getDomainName("account.account.externalroute");
        String quser = user + "@" + domainName;

        Account acct = createAccount(user, domainName);
        Domain domain = getDomain(domainName);

        setupExternalRoute(acct, true, "1", "2", "3", "4");

        NginxLookupRequest req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.pop3.name());
        NginxLookupResponse res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "1");

        req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.pop3ssl.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "2");

        req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.imap.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "3");

        req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.imapssl.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "4");

        deleteAccount(acct);
        deleteDomain(domain);
    }

    @Test
    public void externalRouteOnAccountUseRouteOnAccountUseRouteOnDomain() throws Exception {
        String user = "user";
        String domainName = getDomainName("account.domain.externalroute");
        String quser = user + "@" + domainName;

        Account acct = createAccount(user, domainName);
        setupExternalRoute(acct, true, "", "", "", "");

        Domain domain = getDomain(domainName);
        setupExternalRoute(domain, true, null, "5", "6", "7", "8");

        NginxLookupRequest req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.pop3.name());
        NginxLookupResponse res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "5");

        req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.pop3ssl.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "6");

        req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.imap.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "7");

        req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.imapssl.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "8");

        deleteAccount(acct);
        deleteDomain(domain);
    }

    @Test
    public void externalRouteOnDomainUseRouteOnAccountUseRouteOnAccount() throws Exception {
        String user = "user";
        String domainName = getDomainName("domain.account.externalroute");
        String quser = user + "@" + domainName;

        Account acct = createAccount(user, domainName);
        setupExternalRoute(acct, null, "1", "2", "3", "4");

        Domain domain = getDomain(domainName);
        setupExternalRoute(domain, true, null, "5", "6", "7", "8");

        NginxLookupRequest req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.pop3.name());
        NginxLookupResponse res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "1");

        req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.pop3ssl.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "2");

        req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.imap.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "3");

        req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.imapssl.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "4");

        deleteAccount(acct);
        deleteDomain(domain);
    }

    @Test
    public void externalRouteOnDomainUseRouteOnAccountUseRouteOnDomain() throws Exception {
        String user = "user";
        String domainName = getDomainName("domain.domain.externalroute");
        String quser = user + "@" + domainName;

        Account acct = createAccount(user, domainName);
        setupExternalRoute(acct, null, "", "", "", "");

        Domain domain = getDomain(domainName);
        setupExternalRoute(domain, true, null, "5", "6", "7", "8");

        NginxLookupRequest req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.pop3.name());
        NginxLookupResponse res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "5");

        req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.pop3ssl.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "6");

        req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.imap.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "7");

        req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.imapssl.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "8");

        deleteAccount(acct);
        deleteDomain(domain);
    }

    @Test
    public void externalRouteOnDomainIfAccountNoExistUseRouteOnAccountUseRouteOnDomain() throws Exception {
        String user = "user";
        String domainName = getDomainName("domain.domain.acountNotExist.externalroute");
        String quser = user + "@" + domainName;

        Domain domain = getOrCreateDomain(domainName);
        boolean useExternalRoute = true;
        boolean useExternalRouteIfAccountNotExists = true;
        setupExternalRoute(domain, useExternalRoute, useExternalRouteIfAccountNotExists, "5", "6", "7", "8");

        NginxLookupRequest req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.pop3.name());
        NginxLookupResponse res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "5");

        req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.pop3ssl.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "6");

        req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.imap.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "7");

        req = new NginxLookupRequest(quser, PASSWORD, AuthMethod.plain.name(), AuthProtocol.imapssl.name());
        res = new NginxLookupResponse();
        handler.search(req, res);
        assertBasic(res, quser, LOCALHOST, "8");

        deleteDomain(domain);
    }
}
