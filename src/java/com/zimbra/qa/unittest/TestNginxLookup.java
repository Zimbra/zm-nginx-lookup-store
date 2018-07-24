/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2007, 2008, 2009, 2010, 2011, 2013, 2014, 2016 Synacor, Inc.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation,
 * version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <https://www.gnu.org/licenses/>.
 * ***** END LICENSE BLOCK *****
 */
package com.zimbra.qa.unittest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.Header;
import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

import com.zimbra.common.account.Key;
import com.zimbra.common.account.Key.AccountBy;
import com.zimbra.common.httpclient.HttpClientUtil;
import com.zimbra.common.localconfig.LC;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.soap.AdminConstants;
import com.zimbra.common.util.CliUtil;
import com.zimbra.common.util.ZimbraHttpConnectionManager;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.Config;
import com.zimbra.cs.account.Domain;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.Server;
import com.zimbra.cs.account.soap.SoapProvisioning;
import com.zimbra.cs.httpclient.URLUtil;
import com.zimbra.cs.nginx.NginxLookupExtension;

public class TestNginxLookup {

    @Rule
    public TestName name = new TestName();

    private static SoapProvisioning mSoapProv = null;
    private static final Provisioning prov = Provisioning.getInstance();

    private static final String URL = "https://localhost:7072/service/extension/nginx-lookup";

    // use special chars for testing bug 67370
    private static final String ACCT_LOCALPART = "nginx-lookup!%a|{e-q}$.x&j.^i_l#l~3+*=z?1321332668"; // "user1";
    private static final String ACCT2_LOCALPART = "nginx-lookup-user2";

    private static final String PASSWORD = "test123";

    // private static final String IMAP_HOST = "10.10.131.101";
    // private static final String IMAP_HOST = "192.168.0.162";
    private static String IMAP_HOST_IP = "127.0.0.1";
    private static String IMAP_SSL_HOST_IP = "127.0.0.1";
    private static final String IMAP_PORT = "7143";
    private static final String IMAP_SSL_PORT = "7993";

    // private static final String POP3_HOST = "192.168.0.162";
    private static String POP3_HOST_IP = "127.0.0.1";
    private static String POP3_SSL_HOST_IP = "127.0.0.1";
    private static final String POP3_PORT = "7110";
    private static final String POP3_SSL_PORT = "7995";

    private static String HTTP_HOST_IP = "127.0.0.1";
    private static final String HTTP_PORT    = LC.zimbra_mail_service_port.value();

    private static final String TEST_HOST_DOGFOOD    = "dogfood.zimbra.com";
    private static String TEST_HOST_IP_DOGFOOD = "10.113.63.59"; // "207.126.229.140";
    private static final String TEST_HOST_CATFOOD    = "catfood.zimbra.com";
    private static String TEST_HOST_IP_CATFOOD = "10.113.63.60"; // "207.126.229.141";

    private static final String IMAP_EXTERNAL_HOST = TEST_HOST_DOGFOOD;
    private static String IMAP_EXTERNAL_HOST_IP = TEST_HOST_IP_DOGFOOD;
    private static final String IMAP_EXTERNAL_PORT = "1111";
    private static final String IMAP_SSL_EXTERNAL_HOST = TEST_HOST_CATFOOD;
    private static String IMAP_SSL_EXTERNAL_HOST_IP = TEST_HOST_IP_CATFOOD;
    private static final String IMAP_SSL_EXTERNAL_PORT = "2222";
    private static final String POP3_EXTERNAL_HOST = TEST_HOST_CATFOOD;
    private static String POP3_EXTERNAL_HOST_IP = TEST_HOST_IP_CATFOOD;
    private static final String POP3_EXTERNAL_PORT = "3333";
    private static final String POP3_SSL_EXTERNAL_HOST = TEST_HOST_DOGFOOD;
    private static String POP3_SSL_EXTERNAL_HOST_IP = TEST_HOST_IP_DOGFOOD;
    private static final String POP3_SSL_EXTERNAL_PORT = "4444";

    private static final String IMAP_EXTERNAL_HOST_ON_DOMAIN = TEST_HOST_CATFOOD;
    private static String IMAP_EXTERNAL_HOST_IP_ON_DOMAIN = TEST_HOST_IP_CATFOOD;
    private static final String IMAP_EXTERNAL_PORT_ON_DOMAIN = "5555";
    private static final String IMAP_SSL_EXTERNAL_HOST_ON_DOMAIN = TEST_HOST_DOGFOOD;
    private static String IMAP_SSL_EXTERNAL_HOST_IP_ON_DOMAIN = TEST_HOST_IP_DOGFOOD;
    private static final String IMAP_SSL_EXTERNAL_PORT_ON_DOMAIN = "6666";
    private static final String POP3_EXTERNAL_HOST_ON_DOMAIN = TEST_HOST_DOGFOOD;
    private static String POP3_EXTERNAL_HOST_IP_ON_DOMAIN = TEST_HOST_IP_DOGFOOD;
    private static final String POP3_EXTERNAL_PORT_ON_DOMAIN = "7777";
    private static final String POP3_SSL_EXTERNAL_HOST_ON_DOMAIN = TEST_HOST_CATFOOD;
    private static String POP3_SSL_EXTERNAL_HOST_IP_ON_DOMAIN = TEST_HOST_IP_CATFOOD;
    private static final String POP3_SSL_EXTERNAL_PORT_ON_DOMAIN = "8888";

    private static final String STATUS_OK = "OK";
    private static final String STATUS_LOGIN_FAILED = NginxLookupExtension.NginxLookupHandler.ERRMSG;
    private static final String AUTH_WAIT = "10";
    private static final String FOREIGN_ID = "t12345";

    /*
     * There are three test accounts:
     * ACCT: test account in the test domain, with foreign principal ACCT_FOREIGN_PRINCIPAL
     * ACCT1: account in the default domain with the same local part as ACCT, no foreign principal
     * ACCT2: account in the default domain with different local part as ACCT,
     *        with foreign principal that has the same "FOREIGN_ID" as that for ACCT,
     *        the foreign principal is FOREIGN_ID+"@"SYSTEM_DEFAULT_DOMAIN
     */
    // to be initialized in init
    private static String ACCT_EMAIL;
    private static String ACCT1_EMAIL;
    private static String ACCT2_EMAIL;
    private static String DOMAIN;
    private static String DOMAIN_VIRTUAL_IP;
    private static String SYSTEM_DEFAULT_DOMAIN;
    private static String ACCT_FOREIGN_PRINCIPAL;
    private static String ACCT2_FOREIGN_PRINCIPAL;
    private static List<Account> accts = new ArrayList<Account>();
    private static Account testAcct = null;
    private static Account testAcct1 = null;
    private static Account testAcct2 = null;
    private static Account childAcct = null;
    private static Account parentAcct = null;
    private static List<Domain> domains = new ArrayList<Domain>();

    public static class Result {
        public Result(String status, String server, String port, String user, String wait, String password) {
            mStatus = status;
            mServer = server;
            mPort = port;
            mUser = user;
            mWait = wait;
            mAuthToken = password;  // auth token for gssapi and certauth are returned in the password header
        }

        void verify(String status, String server, String port, String user, String wait) {
            verify(status, server, port, user, wait, false);
        }

        void verify(String status, String server, String port, String user, String wait, boolean hasAuthToken) {
            assertEquals("status not as expected", status, mStatus);
            assertEquals("server not as expected", server, mServer);
            assertEquals("port not as expected", port, mPort);

            /*
             * Strange, user should only be returned when the actual user name(email) is different
             * than the email in the lookup request.  But it seems this behavior has been changed
             * and the Auth-User is always returned.  Not sure if this is intended, leave it since
             * it doesn't seem to break anything.
             */
            if (user != null) {
                assertEquals(user, mUser);
            }
            assertEquals(wait, mWait);

            if (hasAuthToken) {
                assertNotNull(mAuthToken);
            }
        }

        String mStatus;
        String mServer;
        String mPort;
        String mUser;
        String mWait;
        String mAuthToken;
    }

    private static void modifyConfig(Map<String, Object> attrs) throws Exception {
        Config config = mSoapProv.getConfig();
        mSoapProv.modifyAttrs(config, attrs);
    }

    @Before
    public void setUp() throws Exception {

        if (!TestUtil.fromRunUnitTests) {
            CliUtil.toolSetup();
        }
        mSoapProv = new SoapProvisioning();
        Server localServer = prov.getLocalServer();
        mSoapProv.soapSetURI(URLUtil.getAdminURL(localServer, AdminConstants.ADMIN_SERVICE_URI, true));
        mSoapProv.soapZimbraAdminAuthenticate();

        String TEST_ID = name.getMethodName().toLowerCase();
        String TEST_NAME = "test-nginxlookup";

        DOMAIN = TestProvisioningUtil.baseDomainName(TEST_NAME, TEST_ID);

        // revert reverse proxy config to defaults
        unsetLookupByForeignPrincipal();

        InetAddress IP = InetAddress.getLocalHost();
        IMAP_HOST_IP = IP.getHostAddress();
        IMAP_SSL_HOST_IP = IP.getHostAddress();
        POP3_HOST_IP = IP.getHostAddress();
        POP3_SSL_HOST_IP = IP.getHostAddress();
        HTTP_HOST_IP = IP.getHostAddress();
        TEST_HOST_IP_DOGFOOD = InetAddress.getByName(TEST_HOST_DOGFOOD).getHostAddress();
        TEST_HOST_IP_CATFOOD = InetAddress.getByName(TEST_HOST_CATFOOD).getHostAddress();
        IMAP_EXTERNAL_HOST_IP = TEST_HOST_IP_DOGFOOD;
        IMAP_SSL_EXTERNAL_HOST_IP = TEST_HOST_IP_CATFOOD;
        POP3_EXTERNAL_HOST_IP = TEST_HOST_IP_CATFOOD;
        POP3_SSL_EXTERNAL_HOST_IP = TEST_HOST_IP_DOGFOOD;
        IMAP_EXTERNAL_HOST_IP_ON_DOMAIN = TEST_HOST_IP_CATFOOD;
        IMAP_SSL_EXTERNAL_HOST_IP_ON_DOMAIN = TEST_HOST_IP_DOGFOOD;
        POP3_EXTERNAL_HOST_IP_ON_DOMAIN = TEST_HOST_IP_DOGFOOD;
        POP3_SSL_EXTERNAL_HOST_IP_ON_DOMAIN = TEST_HOST_IP_CATFOOD;

        SYSTEM_DEFAULT_DOMAIN = mSoapProv.getConfig().getAttr(Provisioning.A_zimbraDefaultDomainName);
        ACCT_EMAIL = ACCT_LOCALPART + "@" + DOMAIN;
        ACCT1_EMAIL = ACCT_LOCALPART + "@" + SYSTEM_DEFAULT_DOMAIN;
        ACCT2_EMAIL = ACCT2_LOCALPART + "@" + SYSTEM_DEFAULT_DOMAIN;

        // create the domain
        Map<String, Object> domainAttrs = new HashMap<String, Object>();
        // generate a unique IP for this test run so we won't get multiple from search
        SimpleDateFormat fmt =  new SimpleDateFormat("10.HH:mm:ss");
        DOMAIN_VIRTUAL_IP = fmt.format(new Date());
        domainAttrs.put(Provisioning.A_zimbraVirtualIPAddress, DOMAIN_VIRTUAL_IP);
        Domain domain = mSoapProv.createDomain(DOMAIN, domainAttrs);
        assertNotNull(String.format("Unable to create domain %s during setup", DOMAIN), domain);
        domains.add(domain);

        // create the test account
        ACCT_FOREIGN_PRINCIPAL = FOREIGN_ID + "@" + DOMAIN;
        Map<String, Object> acctAttrs = new HashMap<String, Object>();
        acctAttrs.put(Provisioning.A_zimbraForeignPrincipal, ACCT_FOREIGN_PRINCIPAL);
        testAcct = mSoapProv.createAccount(ACCT_EMAIL, PASSWORD, acctAttrs);
        assertNotNull(String.format("Unable to create account %s during setup", ACCT_EMAIL), testAcct);
        accts.add(testAcct);

        /* ACCT1: account in the default domain with the same local part as ACCT, no foreign principal */
        testAcct1 = mSoapProv.createAccount(ACCT1_EMAIL, PASSWORD, null);
        assertNotNull(String.format("Unable to create account %s during setup", ACCT1_EMAIL), testAcct1);
        accts.add(testAcct1);

        // setup external route for the accout
        setupAccountExternalRoute(testAcct);

        testAcct2 = mSoapProv.createAccount(ACCT2_EMAIL, PASSWORD, null);
        assertNotNull(String.format("Unable to create account %s during setup", ACCT2_EMAIL), testAcct2);
        accts.add(testAcct2);
        // set foreign id for an account in the system default domain
        acctAttrs.clear();
        ACCT2_FOREIGN_PRINCIPAL = FOREIGN_ID + "@" +SYSTEM_DEFAULT_DOMAIN;
        acctAttrs.put(Provisioning.A_zimbraForeignPrincipal, ACCT2_FOREIGN_PRINCIPAL);
        mSoapProv.modifyAttrs(testAcct2, acctAttrs);
    }

    @After
    public void shutdown() throws Exception {
        for (Account acct : accts) {
            deleteAccount(acct);
        }
        accts.clear();
        for (Domain dom : domains) {
            deleteDomain(dom);
        }
        domains.clear();
    }

    // revert reverse proxy config to defaults
    private static void unsetLookupByForeignPrincipal() throws Exception {
        Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put(Provisioning.A_zimbraReverseProxyUserNameAttribute, "");
        attrs.put(Provisioning.A_zimbraReverseProxyMailHostQuery, "(|(zimbraMailDeliveryAddress=${USER})(zimbraMailAlias=${USER})(zimbraId=${USER}))");
        modifyConfig(attrs);
    }

    private void setupLookupByForeignPrincipal() throws Exception {
        Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put(Provisioning.A_zimbraReverseProxyUserNameAttribute, "zimbraMailDeliveryAddress");
        attrs.put(Provisioning.A_zimbraReverseProxyMailHostQuery, "(zimbraForeignPrincipal=${USER})");
        modifyConfig(attrs);
    }

    private void unsetAccountExternalRouteFlag(String acctEmail) throws Exception {
        testAcct = mSoapProv.get(AccountBy.name, acctEmail);
        assertNotNull(testAcct);
        Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put(Provisioning.A_zimbraReverseProxyUseExternalRoute, "");
        mSoapProv.modifyAttrs(testAcct, attrs);
    }

    private void setAccountExternalRouteFlag(String acctEmail) throws Exception {
        testAcct = mSoapProv.get(AccountBy.name, acctEmail);
        assertNotNull(testAcct);
        Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put(Provisioning.A_zimbraReverseProxyUseExternalRoute, "TRUE");
        mSoapProv.modifyAttrs(testAcct, attrs);
    }

    private static void setupAccountExternalRoute(Account acct) throws Exception {
        assertNotNull(acct);

        Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put(Provisioning.A_zimbraExternalPop3Port, POP3_EXTERNAL_PORT);
        attrs.put(Provisioning.A_zimbraExternalPop3SSLPort, POP3_SSL_EXTERNAL_PORT);
        attrs.put(Provisioning.A_zimbraExternalImapPort, IMAP_EXTERNAL_PORT);
        attrs.put(Provisioning.A_zimbraExternalImapSSLPort, IMAP_SSL_EXTERNAL_PORT);
        attrs.put(Provisioning.A_zimbraExternalPop3Hostname, POP3_EXTERNAL_HOST);
        attrs.put(Provisioning.A_zimbraExternalPop3SSLHostname, POP3_SSL_EXTERNAL_HOST);
        attrs.put(Provisioning.A_zimbraExternalImapHostname, IMAP_EXTERNAL_HOST);
        attrs.put(Provisioning.A_zimbraExternalImapSSLHostname, IMAP_SSL_EXTERNAL_HOST);

        mSoapProv.modifyAttrs(acct, attrs);
    }

    @Test
    public void testFullEmail() throws Exception {
        // unset the external route flag
        unsetAccountExternalRouteFlag(ACCT_EMAIL);
        doTest(ACCT_EMAIL, PASSWORD, null, "imap").verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, null, null);
        doTest(ACCT_EMAIL, PASSWORD, null, "pop3").verify(STATUS_OK, POP3_HOST_IP, POP3_PORT, null, null);

        // set the external route flag
        setAccountExternalRouteFlag(ACCT_EMAIL);
        doTest(ACCT_EMAIL, PASSWORD, null, "imap").verify(STATUS_OK, IMAP_EXTERNAL_HOST_IP, IMAP_EXTERNAL_PORT, null, null);
        doTest(ACCT_EMAIL, PASSWORD, null, "pop3").verify(STATUS_OK, POP3_EXTERNAL_HOST_IP, POP3_EXTERNAL_PORT, null, null);
    }

    /*
     * should find the account by domain virtual IP
     */
    @Test
    public void testVirtualDomainByProxyIP() throws Exception {
        unsetAccountExternalRouteFlag(ACCT_EMAIL);
        doTest(ACCT_LOCALPART, PASSWORD, DOMAIN_VIRTUAL_IP, "imap").verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, ACCT_EMAIL, null);
        doTest(ACCT_LOCALPART, PASSWORD, DOMAIN_VIRTUAL_IP, "pop3").verify(STATUS_OK, POP3_HOST_IP, POP3_PORT, ACCT_EMAIL, null);

        setAccountExternalRouteFlag(ACCT_EMAIL);
        doTest(ACCT_LOCALPART, PASSWORD, DOMAIN_VIRTUAL_IP, "imap").verify(STATUS_OK, IMAP_EXTERNAL_HOST_IP, IMAP_EXTERNAL_PORT, ACCT_EMAIL, null);
        doTest(ACCT_LOCALPART, PASSWORD, DOMAIN_VIRTUAL_IP, "pop3").verify(STATUS_OK, POP3_EXTERNAL_HOST_IP, POP3_EXTERNAL_PORT, ACCT_EMAIL, null);
    }

    /*
     * should find the account in the default domain
     */
    @Test
    public void testVirtualDomainWrongProxyIP() throws Exception {
        doTest(ACCT_LOCALPART, PASSWORD, "127.0.0.2", "imap").verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, ACCT1_EMAIL, null);
        doTest(ACCT_LOCALPART, PASSWORD, "127.0.0.2", "pop3").verify(STATUS_OK, POP3_HOST_IP, POP3_PORT, ACCT1_EMAIL, null);
    }

    /*
     * should find the account in the default domain
     */
    @Test
    public void testVirtualDomainNoProxyIP() throws Exception {
        doTest(ACCT_LOCALPART, PASSWORD, null, "imap").verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, ACCT1_EMAIL, null);
        doTest(ACCT_LOCALPART, PASSWORD, null, "pop3").verify(STATUS_OK, POP3_HOST_IP, POP3_PORT, ACCT1_EMAIL, null);
    }


    private Domain setupExternalRouteDomain(String domainName) throws Exception {
        Domain domain = mSoapProv.get(Key.DomainBy.name, domainName);

        if (domain == null) {
            Map<String, Object> attrs = new HashMap<String, Object>();
            attrs.put(Provisioning.A_zimbraExternalPop3Port, POP3_EXTERNAL_PORT_ON_DOMAIN);
            attrs.put(Provisioning.A_zimbraExternalPop3SSLPort, POP3_SSL_EXTERNAL_PORT_ON_DOMAIN);
            attrs.put(Provisioning.A_zimbraExternalImapPort, IMAP_EXTERNAL_PORT_ON_DOMAIN);
            attrs.put(Provisioning.A_zimbraExternalImapSSLPort, IMAP_SSL_EXTERNAL_PORT_ON_DOMAIN);
            attrs.put(Provisioning.A_zimbraExternalPop3Hostname, POP3_EXTERNAL_HOST_ON_DOMAIN);
            attrs.put(Provisioning.A_zimbraExternalPop3SSLHostname, POP3_SSL_EXTERNAL_HOST_ON_DOMAIN);
            attrs.put(Provisioning.A_zimbraExternalImapHostname, IMAP_EXTERNAL_HOST_ON_DOMAIN);
            attrs.put(Provisioning.A_zimbraExternalImapSSLHostname, IMAP_SSL_EXTERNAL_HOST_ON_DOMAIN);

            domain = mSoapProv.createDomain(domainName, attrs);
            domains.add(domain);
        }
        assertNotNull(domain);
        return domain;
    }

    @Test
    public void testExternalRouteOnAccount() throws Exception {
        String domainName = "external-route." + DOMAIN;
        setupExternalRouteDomain(domainName);

        String acctEmail = "nginx-lookup-user1@" + domainName;
        Account acct = mSoapProv.createAccount(acctEmail, PASSWORD, null);
        accts.add(acct);

        setAccountExternalRouteFlag(acctEmail);
        setupAccountExternalRoute(acct);

        doTest(acctEmail, PASSWORD, null, "imap").verify(STATUS_OK, IMAP_EXTERNAL_HOST_IP, IMAP_EXTERNAL_PORT, null, null);
        doTest(acctEmail, PASSWORD, null, "pop3").verify(STATUS_OK, POP3_EXTERNAL_HOST_IP, POP3_EXTERNAL_PORT, null, null);
        doTest(acctEmail, PASSWORD, null, "imapssl").verify(STATUS_OK, IMAP_SSL_EXTERNAL_HOST_IP, IMAP_SSL_EXTERNAL_PORT, null, null);
        doTest(acctEmail, PASSWORD, null, "pop3ssl").verify(STATUS_OK, POP3_SSL_EXTERNAL_HOST_IP, POP3_SSL_EXTERNAL_PORT, null, null);

        // external route only applies to pop3/imap, not http
        doTest(acctEmail, PASSWORD, null, "http").verify(STATUS_OK, HTTP_HOST_IP, HTTP_PORT, null, null);

    }

    @Test
    public void testExternalRouteOnDomain() throws Exception {
        String domainName = "external-route." + DOMAIN;
        setupExternalRouteDomain(domainName);

        String acctEmail = "nginx-lookup-user2@" + domainName;
        Account acct = mSoapProv.createAccount(acctEmail, PASSWORD, null);
        accts.add(acct);

        setAccountExternalRouteFlag(acctEmail);

        doTest(acctEmail, PASSWORD, null, "imap").verify(STATUS_OK, IMAP_EXTERNAL_HOST_IP_ON_DOMAIN, IMAP_EXTERNAL_PORT_ON_DOMAIN, null, null);
        doTest(acctEmail, PASSWORD, null, "pop3").verify(STATUS_OK, POP3_EXTERNAL_HOST_IP_ON_DOMAIN, POP3_EXTERNAL_PORT_ON_DOMAIN, null, null);
        doTest(acctEmail, PASSWORD, null, "imapssl").verify(STATUS_OK, IMAP_SSL_EXTERNAL_HOST_IP_ON_DOMAIN, IMAP_SSL_EXTERNAL_PORT_ON_DOMAIN, null, null);
        doTest(acctEmail, PASSWORD, null, "pop3ssl").verify(STATUS_OK, POP3_SSL_EXTERNAL_HOST_IP_ON_DOMAIN, POP3_SSL_EXTERNAL_PORT_ON_DOMAIN, null, null);

        // external route only applies to pop3/imap, not http
        doTest(acctEmail, PASSWORD, null, "http").verify(STATUS_OK, HTTP_HOST_IP, HTTP_PORT, null, null);

        // set partial external route on account, should still fallback to the domain external route
        // settings, because the setting on account is not complete.
        Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put(Provisioning.A_zimbraExternalPop3Hostname, POP3_EXTERNAL_HOST_ON_DOMAIN);
        attrs.put(Provisioning.A_zimbraExternalPop3SSLHostname, POP3_SSL_EXTERNAL_HOST_ON_DOMAIN);
        attrs.put(Provisioning.A_zimbraExternalImapHostname, IMAP_EXTERNAL_HOST_ON_DOMAIN);
        attrs.put(Provisioning.A_zimbraExternalImapSSLHostname, IMAP_SSL_EXTERNAL_HOST_ON_DOMAIN);
        mSoapProv.modifyAttrs(acct, attrs);

        doTest(acctEmail, PASSWORD, null, "imap").verify(STATUS_OK, IMAP_EXTERNAL_HOST_IP_ON_DOMAIN, IMAP_EXTERNAL_PORT_ON_DOMAIN, null, null);
        doTest(acctEmail, PASSWORD, null, "pop3").verify(STATUS_OK, POP3_EXTERNAL_HOST_IP_ON_DOMAIN, POP3_EXTERNAL_PORT_ON_DOMAIN, null, null);
        doTest(acctEmail, PASSWORD, null, "imapssl").verify(STATUS_OK, IMAP_SSL_EXTERNAL_HOST_IP_ON_DOMAIN, IMAP_SSL_EXTERNAL_PORT_ON_DOMAIN, null, null);
        doTest(acctEmail, PASSWORD, null, "pop3ssl").verify(STATUS_OK, POP3_SSL_EXTERNAL_HOST_IP_ON_DOMAIN, POP3_SSL_EXTERNAL_PORT_ON_DOMAIN, null, null);
    }

    @Test
    public void testExternalRouteMissingExternalRouteInfo() throws Exception {
        String domainName = "external-route-missing-info." + DOMAIN;
        domains.add(mSoapProv.createDomain(domainName, null));  // create the domain with no external route info

        String acctEmail = "user@" + domainName;
        accts.add(mSoapProv.createAccount(acctEmail, PASSWORD, null));  // create account with no external route info

        setAccountExternalRouteFlag(acctEmail);  // turn on the use external route flag on account

        // should all fallback to internal route
        doTest(acctEmail, PASSWORD, null, "imap").verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, null, null);
        doTest(acctEmail, PASSWORD, null, "pop3").verify(STATUS_OK, POP3_HOST_IP, POP3_PORT, null, null);
        doTest(acctEmail, PASSWORD, null, "imapssl").verify(STATUS_OK, IMAP_SSL_HOST_IP, IMAP_SSL_PORT, null, null);
        doTest(acctEmail, PASSWORD, null, "pop3ssl").verify(STATUS_OK, POP3_SSL_HOST_IP, POP3_SSL_PORT, null, null);
    }

    /*
        NGINX will no longer pass any suffixes(/tb|/wm|/ni) to the lookup servlet, see p4 change 107019.

        Skip all the Extension tests.  orig bug: 20542
    */
    @Test
    @Ignore
    public void testSupportedExtensionFullEmail() throws Exception {
        doTest(ACCT_EMAIL+"/tb", PASSWORD, DOMAIN_VIRTUAL_IP, "imap").verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, null, null);
        doTest(ACCT_EMAIL+"/tb", PASSWORD, DOMAIN_VIRTUAL_IP, "pop3").verify(STATUS_OK, POP3_HOST_IP, POP3_PORT, null, null);
    }

    @Test
    @Ignore
    public void testSupportedExtensionVirtualDomain() throws Exception {
        doTest(ACCT_LOCALPART+"/tb", PASSWORD, DOMAIN_VIRTUAL_IP, "imap").verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, ACCT_EMAIL+"/tb", null);
        doTest(ACCT_LOCALPART+"/tb", PASSWORD, DOMAIN_VIRTUAL_IP, "pop3").verify(STATUS_OK, POP3_HOST_IP, POP3_PORT, ACCT_EMAIL+"/tb", null);
    }

    @Test
    @Ignore
    public void testUnsupportedExtension() throws Exception {
        doTest(ACCT_LOCALPART + "/zz", PASSWORD, DOMAIN_VIRTUAL_IP, "imap").verify(STATUS_LOGIN_FAILED, null, null, null, AUTH_WAIT);
        doTest(ACCT_LOCALPART + "/zz", PASSWORD, DOMAIN_VIRTUAL_IP, "pop3").verify(STATUS_LOGIN_FAILED, null, null, null, AUTH_WAIT);
    }

    @Test
    public void testLookupByForeignPrincipalFullEmail()  throws Exception {
        setupLookupByForeignPrincipal();
        unsetAccountExternalRouteFlag(ACCT_EMAIL);

        // full email
        doTest(ACCT_FOREIGN_PRINCIPAL, PASSWORD, null, "imap").verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, ACCT_EMAIL, null);
        doTest(ACCT_FOREIGN_PRINCIPAL, PASSWORD, null, "pop3").verify(STATUS_OK, POP3_HOST_IP, POP3_PORT, ACCT_EMAIL, null);

        setAccountExternalRouteFlag(ACCT_EMAIL);
        doTest(ACCT_FOREIGN_PRINCIPAL, PASSWORD, null, "imap").verify(STATUS_OK, IMAP_EXTERNAL_HOST_IP, IMAP_EXTERNAL_PORT, ACCT_EMAIL, null);
        doTest(ACCT_FOREIGN_PRINCIPAL, PASSWORD, null, "pop3").verify(STATUS_OK, POP3_EXTERNAL_HOST_IP, POP3_EXTERNAL_PORT, ACCT_EMAIL, null);

        /*
        // full email with supported extension
        doTest(ACCT_FOREIGN_PRINCIPAL+"/tb", PASSWORD, null, "imap").verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, ACCT_EMAIL+"/tb", null);
        doTest(ACCT_FOREIGN_PRINCIPAL+"/tb", PASSWORD, null, "pop3").verify(STATUS_OK, POP3_HOST_IP, POP3_PORT, ACCT_EMAIL+"/tb", null);

        // full email with unsupported extension
        doTest(ACCT_FOREIGN_PRINCIPAL+"/zz", PASSWORD, null, "imap").verify(STATUS_LOGIN_FAILED, null, null, null, AUTH_WAIT);
        doTest(ACCT_FOREIGN_PRINCIPAL+"/zz", PASSWORD, null, "pop3").verify(STATUS_LOGIN_FAILED, null, null, null, AUTH_WAIT);
        */

        unsetLookupByForeignPrincipal();
    }

    @Test
    public void testLookupByForeignPrincipalVirtualDomain() throws Exception {
        setupLookupByForeignPrincipal();

        unsetAccountExternalRouteFlag(ACCT_EMAIL);

        // virtual domain by proxy IP
        doTest(FOREIGN_ID, PASSWORD, DOMAIN_VIRTUAL_IP, "imap").verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, ACCT_EMAIL, null);
        doTest(FOREIGN_ID, PASSWORD, DOMAIN_VIRTUAL_IP, "pop3").verify(STATUS_OK, POP3_HOST_IP, POP3_PORT, ACCT_EMAIL, null);

        setAccountExternalRouteFlag(ACCT_EMAIL);
        doTest(FOREIGN_ID, PASSWORD, DOMAIN_VIRTUAL_IP, "imap").verify(STATUS_OK, IMAP_EXTERNAL_HOST_IP, IMAP_EXTERNAL_PORT, ACCT_EMAIL, null);
        doTest(FOREIGN_ID, PASSWORD, DOMAIN_VIRTUAL_IP, "pop3").verify(STATUS_OK, POP3_EXTERNAL_HOST_IP, POP3_EXTERNAL_PORT, ACCT_EMAIL, null);

        // virtual domain wrong proxy IP, the foreign id + default domain exists
        doTest(FOREIGN_ID, PASSWORD, "127.0.0.2", "imap").verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, ACCT2_EMAIL, null);
        doTest(FOREIGN_ID, PASSWORD, "127.0.0.2", "pop3").verify(STATUS_OK, POP3_HOST_IP, POP3_PORT, ACCT2_EMAIL, null);

        // virtual domain wrong proxy IP, the foreign id + default domain does not exist
        /*
         * behavior changed after p4 change 334496, it is correct?
         * prior to p4 change 334496, expected status was STATUS_LOGIN_FAILED
         */
        String expectedStatus = "user not found:" + FOREIGN_ID+"wrong" + "@" + SYSTEM_DEFAULT_DOMAIN;
        doTest(FOREIGN_ID+"wrong", PASSWORD, "127.0.0.2", "imap").verify(expectedStatus, null, null, null, AUTH_WAIT);
        doTest(FOREIGN_ID+"wrong", PASSWORD, "127.0.0.2", "pop3").verify(expectedStatus, null, null, null, AUTH_WAIT);

        // virtual domain no proxy IP
        doTest(FOREIGN_ID, PASSWORD, null, "imap").verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, ACCT2_EMAIL, null);
        doTest(FOREIGN_ID, PASSWORD, null, "pop3").verify(STATUS_OK, POP3_HOST_IP, POP3_PORT, ACCT2_EMAIL, null);

        /*
        // virtual domain with supported extension
        doTest(FOREIGN_ID+"/tb", PASSWORD, DOMAIN_VIRTUAL_IP, "imap").verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, ACCT_EMAIL+"/tb", null);
        doTest(FOREIGN_ID+"/tb", PASSWORD, DOMAIN_VIRTUAL_IP, "pop3").verify(STATUS_OK, POP3_HOST_IP, POP3_PORT, ACCT_EMAIL+"/tb", null);

        // virtual domain with unsupported extension
        doTest(FOREIGN_ID+"/zz", PASSWORD, DOMAIN_VIRTUAL_IP, "imap").verify(STATUS_LOGIN_FAILED, null, null, null, AUTH_WAIT);
        doTest(FOREIGN_ID+"/zz", PASSWORD, DOMAIN_VIRTUAL_IP, "pop3").verify(STATUS_LOGIN_FAILED, null, null, null, AUTH_WAIT);
        */

        unsetLookupByForeignPrincipal();
    }

    @Ignore("Needs Kerberos realm setup")
    @Test
    public void testGssApi() throws Exception {

        /*
        zmprov md phoebe.mac zimbraAuthKerberos5Realm ZIMBRA.COM zimbraVirtualIPAddress 13.12.11.10
        zmprov mcf zimbraReverseProxyAdminIPAddress 13.12.11.10
        */

        // domain
        String domainName = DOMAIN;
        Domain testDomain = mSoapProv.get(Key.DomainBy.name, domainName);

        // test account names
        String acctLocalPart = "gssapi-test";
        String acctEmail = acctLocalPart + "@" + domainName;
        String otherAcctLocalPart = "gssapi-test-other";
        String otherAcctEmail = otherAcctLocalPart + "@" + domainName;

        // krb5 realm/principal
        // generate a unique realm for this test
        SimpleDateFormat fmtRealm =  new SimpleDateFormat("HH-mm-ss-");
        String krb5Realm = fmtRealm.format(new Date()) + "ZIMBRA.COM";
        String acctKrb5Principal = acctLocalPart + "@" + krb5Realm;

        // admin account
        String adminAcct = "zmnginx";
        String adminPassword = "zmnginx";  // from ZimbraServer/conf/ldap/zimbra.ldif

        // simulating nginx server IP and remote client IP.
        // generate a unique IP for this test
        SimpleDateFormat fmtIp =  new SimpleDateFormat("10.HH:mm:ss");
        String nginxServerIp = fmtIp.format(new Date()); // "13.12.11.10";
        String clientIp = "11.22.33.44"; // doesn't really matter

        // create test accounts
        accts.add(mSoapProv.createAccount(acctEmail, PASSWORD, null));
        accts.add(mSoapProv.createAccount(otherAcctEmail, PASSWORD, null));

        // setup domain
        Map<String, Object> attrs = new HashMap<String, Object>();
        attrs.put(Provisioning.A_zimbraAuthKerberos5Realm, krb5Realm);
        attrs.put(Provisioning.A_zimbraVirtualIPAddress, nginxServerIp);
        mSoapProv.modifyAttrs(testDomain, attrs);

        // setup global config
        Config config = mSoapProv.getConfig();
        attrs.clear();
        attrs.put(Provisioning.A_zimbraReverseProxyAdminIPAddress, nginxServerIp);
        mSoapProv.modifyAttrs(config, attrs);

        // family mailbox
        String childLocalPart = "child";
        String childEmail = childLocalPart +  "@" + domainName;
        childAcct = mSoapProv.createAccount(childEmail, PASSWORD, null);
        accts.add(childAcct);

        String parentLocalPart = "parent";
        String parentEmail = parentLocalPart + "@" + domainName;
        String parentKrb5Principal = parentLocalPart + "@" + krb5Realm;
        attrs.clear();
        attrs.put(Provisioning.A_zimbraChildAccount, childAcct.getId());
        parentAcct = mSoapProv.createAccount(parentEmail, PASSWORD, attrs);
        accts.add(parentAcct);

        doTest("gssapi",  acctLocalPart,      null,  "imap",  "1",  clientIp,  nginxServerIp,  null,  acctKrb5Principal,  adminAcct,  adminPassword).
                verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, acctEmail, null);
        doTest("gssapi",  acctEmail,          null,  "imap",  "1",  clientIp,  nginxServerIp,  null,  acctKrb5Principal,  adminAcct,  adminPassword).
                verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, acctEmail, null);
        doTest("gssapi",  acctKrb5Principal,  null,  "imap",  "1",  clientIp,  nginxServerIp,  null,  acctKrb5Principal,  adminAcct,  adminPassword).
                verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, acctEmail, null);

        /*
         * behavior changed after p4 change 334496, it is correct?
         * prior to p4 change 334496, expected status was STATUS_LOGIN_FAILED
         */
        String expectedStatus = String.format(
                "authorization failed for %s (authenticated user %s has insufficient rights)",
                otherAcctLocalPart + "@" + DOMAIN,
                acctLocalPart + "@" + DOMAIN);
        doTest("gssapi",  otherAcctLocalPart, null,  "imap",  "1",  clientIp,  nginxServerIp,  null,  acctKrb5Principal,  adminAcct,  adminPassword).
                verify(expectedStatus, null, null, null, AUTH_WAIT);

        /*
         * behavior changed after p4 change 334496, it is correct?
         * prior to p4 change 334496, expected status was STATUS_LOGIN_FAILED
         */
        expectedStatus = "admin account zmnginxbogus not found";
        doTest("gssapi",  acctLocalPart,      null,  "imap",  "1",  clientIp,  nginxServerIp,  null,  acctKrb5Principal,  "zmnginxbogus",  adminPassword).
                verify(expectedStatus, null, null, null, AUTH_WAIT);

        doTest("gssapi",  childLocalPart,     null,  "imap",  "1",  clientIp,  nginxServerIp,  null,  parentKrb5Principal,  adminAcct,  adminPassword).
                verify(STATUS_OK, IMAP_HOST_IP, IMAP_PORT, childEmail, null);

        // cleanup setting on global config
        attrs.clear();
        attrs.put(Provisioning.A_zimbraReverseProxyAdminIPAddress, "");
        mSoapProv.modifyAttrs(config, attrs);
    }

    @Ignore("Needs proper certificate installation")
    @Test
    public void testCertAuth() throws Exception {
        // admin account
        String adminAcct = "zmnginx";
        String adminPassword = "zmnginx";  // from ZimbraServer/conf/ldap/zimbra.ldif

        // simulating nginx server IP and remote client IP.
        // generate a unique IP for this test
        SimpleDateFormat fmtIp =  new SimpleDateFormat("10.HH:mm:ss");
        String nginxServerIp = fmtIp.format(new Date()); // "13.12.11.10";
        String clientIp = "11.22.33.44"; // doesn't really matter

        // setup global config
        Map<String, Object> attrs = new HashMap<String, Object>();
        Config config = mSoapProv.getConfig();
        attrs.clear();
        attrs.put(Provisioning.A_zimbraReverseProxyAdminIPAddress, nginxServerIp);
        mSoapProv.modifyAttrs(config, attrs);

        String acctEmail = "user1@phoebe.mbp";
        String x509SubjectDN = "EMAILADDRESS=user1@phoebe.mbp,CN=user one,OU=Engineering,O=Example Company,L=Saratoga,ST=California,C=US";  // TODO, do not hardcode

        doTest("certauth", x509SubjectDN, null,  "http",  "1",  clientIp,  nginxServerIp,  null,  null,  adminAcct,  adminPassword).
                verify(STATUS_OK, HTTP_HOST_IP, HTTP_PORT, acctEmail, null, true);

        // cleanup setting on global config
        attrs.clear();
        attrs.put(Provisioning.A_zimbraReverseProxyAdminIPAddress, "");
        mSoapProv.modifyAttrs(config, attrs);
    }

    private Result doLookupReq(HttpClientBuilder client, HttpGet method) {
        try {
            HttpResponse response = HttpClientUtil.executeMethod(client.build(), method);

            Header authStatus = response.getFirstHeader(NginxLookupExtension.NginxLookupHandler.AUTH_STATUS);
            Header authServer = response.getFirstHeader(NginxLookupExtension.NginxLookupHandler.AUTH_SERVER);
            Header authPort = response.getFirstHeader(NginxLookupExtension.NginxLookupHandler.AUTH_PORT);
            Header authUser = response.getFirstHeader(NginxLookupExtension.NginxLookupHandler.AUTH_USER);
            Header authWait = response.getFirstHeader(NginxLookupExtension.NginxLookupHandler.AUTH_WAIT);
            Header authPassword = response.getFirstHeader(NginxLookupExtension.NginxLookupHandler.AUTH_PASS);

            return new Result(authStatus==null?null:authStatus.getValue(),
                              authServer==null?null:authServer.getValue(),
                              authPort==null?null:authPort.getValue(),
                              authUser==null?null:simulateNginxDecodeUser(authUser.getValue()),
                              authWait==null?null:authWait.getValue(),
                              authPassword==null?null:authPassword.getValue());

        } catch (IOException | HttpException e) {
            ZimbraLog.test.error("Failed to do Lookup request for test %s", name.getMethodName(), e);
        }

        return null;
    }

    private Result doTest(String user, String pass, String serverIp, String protocol) {
        return doTest("plain", user, pass, protocol, null, null, serverIp, null, null, null, null);
    }

    private Result doTest(String h_AUTH_METHOD,
                                 String h_AUTH_USER,
                                 String h_AUTH_PASS,
                                 String h_AUTH_PROTOCOL,
                                 String h_AUTH_LOGIN_ATTEMPT,
                                 String h_CLIENT_IP,
                                 String h_SERVER_IP,
                                 String h_SERVER_HOST,
                                 String h_AUTH_ID,
                                 String h_AUTH_ADMIN_USER,
                                 String h_AUTH_ADMIN_PASS) {

        HttpClientBuilder client = ZimbraHttpConnectionManager.getInternalHttpConnMgr().newHttpClient();
        HttpGet method = new HttpGet(URL);

        method.addHeader("Host", "localhost");
        if (h_AUTH_METHOD != null)
            method.addHeader(NginxLookupExtension.NginxLookupHandler.AUTH_METHOD, h_AUTH_METHOD);


        if (h_AUTH_USER != null) {
            String nginxEncoded = similateNginxEncodeUserAndPass(h_AUTH_USER);
            method.addHeader(NginxLookupExtension.NginxLookupHandler.AUTH_USER, nginxEncoded);
        }

        if (h_AUTH_PASS != null) {
            String nginxEncoded = similateNginxEncodeUserAndPass(h_AUTH_PASS);
            method.addHeader(NginxLookupExtension.NginxLookupHandler.AUTH_PASS, nginxEncoded);
        }

        if (h_AUTH_PROTOCOL != null)
            method.addHeader(NginxLookupExtension.NginxLookupHandler.AUTH_PROTOCOL, h_AUTH_PROTOCOL);
        if (h_AUTH_LOGIN_ATTEMPT != null)
            method.addHeader(NginxLookupExtension.NginxLookupHandler.AUTH_LOGIN_ATTEMPT, h_AUTH_LOGIN_ATTEMPT);
        if (h_CLIENT_IP != null)
            method.addHeader(NginxLookupExtension.NginxLookupHandler.CLIENT_IP, h_CLIENT_IP);
        if (h_SERVER_IP != null)
            method.addHeader(NginxLookupExtension.NginxLookupHandler.SERVER_IP, h_SERVER_IP);
        if (h_SERVER_HOST != null)
            method.addHeader(NginxLookupExtension.NginxLookupHandler.SERVER_HOST, h_SERVER_HOST);
        if (h_AUTH_ID != null)
            method.addHeader(NginxLookupExtension.NginxLookupHandler.AUTH_ID, h_AUTH_ID);
        if (h_AUTH_ADMIN_USER != null)
            method.addHeader(NginxLookupExtension.NginxLookupHandler.AUTH_ADMIN_USER, h_AUTH_ADMIN_USER);
        if (h_AUTH_ADMIN_PASS != null)
            method.addHeader(NginxLookupExtension.NginxLookupHandler.AUTH_ADMIN_PASS, h_AUTH_ADMIN_PASS);

        return doLookupReq(client, method);
    }

    /*
     * bug 51672
     * Simulate nginx behavior described in http://bugzilla.zimbra.com/show_bug.cgi?id=51672#c4
     * According to that, nginx encode '%' to '%25', and ' ' to '%20'.
     *
     * '%25' will be un-escaped to '%' and '%20' will be un-escaped to ' ' in the lookup servlet.
     * (by p4 change 253790)
     */
    private static String similateNginxEncodeUserAndPass(String in) {
        return in.replaceAll("%", "%25").replaceAll(" ", "%20");
    }

    /*
     * By p4 change 253790
     * lookup servlet replaces '%' to '%25' and ' ' to '%20' when it returns AUTH_USER
     */
    private static String simulateNginxDecodeUser(String in) {
        return in.replaceAll("%25", "%").replaceAll("%20", " ");
    }

    private void deleteAccount(Account acct) throws ServiceException {
        if (acct == null) {
            return;
        }
        prov.deleteAccount(acct.getId());
    }

    private void deleteDomain(Domain domain) throws ServiceException {
        if (domain == null) {
            return;
        }
        prov.deleteDomain(domain.getId());
    }

    /*
    public static void main(String args[]) {
        TestUtil.runTest(TestNginxLookup.class);
    }
    */
}
