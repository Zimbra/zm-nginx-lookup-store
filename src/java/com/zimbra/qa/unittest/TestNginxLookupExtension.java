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

package com.zimbra.qa.unittest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.apache.http.Header;
import org.apache.http.HttpException;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

import com.google.common.base.Joiner;
import com.zimbra.common.account.Key;
import com.zimbra.common.httpclient.HttpClientUtil;
import com.zimbra.common.localconfig.LC;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.ZimbraHttpConnectionManager;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.Domain;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.nginx.NginxLookupExtension;

/*
 * Note: restart server after each run, the lookup servlet caches things
 *       TODO: send a flush cache command to the lookup servlet
 */
public class TestNginxLookupExtension {

    @Rule
    public TestName testInfo = new TestName();

    private static String USER;
    private Domain externalRouteDomain = null;
    private Account externalRouteAccount = null;
    private static String DEFAULT_DOMAIN = null;

    private static String QUSER = USER + "@" +DEFAULT_DOMAIN;

    private static final String PASSWORD = "test123";

    private static final String LOCALHOST = "localhost";
    private static final String LOCALHOST_IP = "127.0.0.1";
    private static String MY_IP_ADDRESS = null;

    private static final String POP3_PORT     = "7110";
    private static final String POP3_SSL_PORT = "7995";
    private static final String IMAP_PORT     = "7143";
    private static final String IMAP_SSL_PORT = "7993";
    private static final String IMAP_DAEMON_PORT     = "8143";
    private static final String IMAP_DAEMON_SSL_PORT = "8993";
    private static final String HTTP_PORT     = LC.zimbra_mail_service_port.value();

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

    private static class LookupData {
        // required
        private AuthMethod mAuthMethod;
        private String mAuthUser;
        private String mAuthPass;
        private AuthProtocol mAuthProtocol;

        protected LookupData(AuthMethod authMethod, String authUser, String authPass, AuthProtocol authProtocol) {
            setAuthMethod(authMethod);
            setAuthUser(authUser);
            setAuthPass(authPass);
            setAuthProtocol(authProtocol);
        }

        protected void setAuthMethod(AuthMethod authMethod) {
            mAuthMethod = authMethod;
        }

        protected void setAuthUser(String authUser) {
            mAuthUser = authUser;
        }

        protected void setAuthPass(String authPass) {
            mAuthPass = authPass;
        }

        protected void setAuthProtocol(AuthProtocol authProtocol) {
            mAuthProtocol = authProtocol;
        }

        /*
        String h_AUTH_LOGIN_ATTEMPT,
        String h_CLIENT_IP,
        String h_SERVER_IP,
        String h_SERVER_HOST,
        String h_AUTH_ID,
        String h_AUTH_ADMIN_USER,
        String h_AUTH_ADMIN_PASS,
        */

        protected void setRequestHeader(HttpGet method) {
            if (mAuthMethod != null)
                method.addHeader(NginxLookupExtension.NginxLookupHandler.AUTH_METHOD, mAuthMethod.name());
            if (mAuthUser != null)
                method.addHeader(NginxLookupExtension.NginxLookupHandler.AUTH_USER, mAuthUser);
            if (mAuthPass != null)
                method.addHeader(NginxLookupExtension.NginxLookupHandler.AUTH_PASS, mAuthPass);
            if (mAuthProtocol != null)
                method.addHeader(NginxLookupExtension.NginxLookupHandler.AUTH_PROTOCOL, mAuthProtocol.name());
            /*
            if (h_AUTH_LOGIN_ATTEMPT != null)
                method.setRequestHeader(NginxLookupExtension.NginxLookupHandler.AUTH_LOGIN_ATTEMPT, h_AUTH_LOGIN_ATTEMPT);
            if (h_CLIENT_IP != null)
                method.setRequestHeader(NginxLookupExtension.NginxLookupHandler.CLIENT_IP, h_CLIENT_IP);
            if (h_SERVER_IP != null)
                method.setRequestHeader(NginxLookupExtension.NginxLookupHandler.SERVER_IP, h_SERVER_IP);
            if (h_SERVER_HOST != null)
                method.setRequestHeader(NginxLookupExtension.NginxLookupHandler.SERVER_HOST, h_SERVER_HOST);
            if (h_AUTH_ID != null)
                method.setRequestHeader(NginxLookupExtension.NginxLookupHandler.AUTH_ID, h_AUTH_ID);
            if (h_AUTH_ADMIN_USER != null)
                method.setRequestHeader(NginxLookupExtension.NginxLookupHandler.AUTH_ADMIN_USER, h_AUTH_ADMIN_USER);
            if (h_AUTH_ADMIN_PASS != null)
                method.setRequestHeader(NginxLookupExtension.NginxLookupHandler.AUTH_ADMIN_PASS, h_AUTH_ADMIN_PASS);
            */
        }
    }

    private static class RespHeaders {
        private final Map<String, String> mHeaders = new HashMap<String, String>();

        protected void add(Header header) {
            mHeaders.put(header.getName(), header.getValue());
        }

        protected String authStatus() {
            return mHeaders.get(NginxLookupExtension.NginxLookupHandler.AUTH_STATUS);
        }

        protected String authUser() {
            return mHeaders.get(NginxLookupExtension.NginxLookupHandler.AUTH_USER);
        }

        protected String authServer() {
            return mHeaders.get(NginxLookupExtension.NginxLookupHandler.AUTH_SERVER);
        }

        protected String authPort() {
            return mHeaders.get(NginxLookupExtension.NginxLookupHandler.AUTH_PORT);
        }


        protected void assertAuthStatusOK() {
            assertEquals("Auth Status", "OK", authStatus());
        }

        protected void assertAuthUser(String expected) {
            assertEquals("Auth User", expected, authUser());
        }

        protected void assertAuthServer(String expected) {
            assertEquals("Auth server", expected, authServer());
        }

        protected void assertAuthPort(String expected) {
            assertEquals("Auth port", expected, authPort());
        }

        protected void assertAuthPort(String[] expected) {
            String port = authPort();
            assertTrue(String.format(
                    "Auth port %s should be one of [%s']", port, Joiner.on(',').join(expected)),
                    Arrays.asList(expected).contains(port));
        }

        protected void assertBasic(String expectedUser, String expectedServer, String expectedPort) {
            assertAuthStatusOK();
            assertAuthUser(expectedUser);
            // setupExternalRoute uses localhost as a test target which naturally maps to 127.0.0.1
            // Was fooled into thinking that when the error reported the IP address of the mailbox
            // instead of this, that was a benign failure.  Changed to validating port before server
            // as it will be more obvious there is a genuine problem then.
            assertAuthPort(expectedPort);
            assertAuthServer(expectedServer);
        }

        protected void assertBasic(String expectedUser, String expectedServer, String[] expectedPorts) {
            assertAuthStatusOK();
            assertAuthUser(expectedUser);
            // setupExternalRoute uses localhost as a test target which naturally maps to 127.0.0.1
            // Was fooled into thinking that when the error reported the IP address of the mailbox
            // instead of this, that was a benign failure.  Changed to validating port before server
            // as it will be more obvious there is a genuine problem then.
            assertAuthPort(expectedPorts);
            assertAuthServer(expectedServer);
        }
    }

    private RespHeaders senRequest(LookupData lookupData) throws IOException, HttpException {
        String url = "https://localhost:7072/service/extension/nginx-lookup";

        HttpClientBuilder client = ZimbraHttpConnectionManager.getInternalHttpConnMgr().newHttpClient();
        HttpGet method = new HttpGet(url);

        method.addHeader("Host", "localhost");
        lookupData.setRequestHeader(method);

        RespHeaders respHdrs = new RespHeaders();
        try {
            HttpResponse response = HttpClientUtil.executeMethod(client.build(), method);

            for (Header header : response.getAllHeaders())
                respHdrs.add(header);

        } catch (IOException | HttpException e) {
            ZimbraLog.test.error("Problem executing HTTP method", e);
            throw e;
        }

        return respHdrs;
    }

    private Provisioning getProv() {
        return Provisioning.getInstance();
    }

    private Account createAccount(String localpart, String domainName) throws ServiceException {
        Domain domain = getDomain(domainName);
        if (domain == null)
            createDomain(domainName);
        return getProv().createAccount(localpart+"@"+domainName, PASSWORD, new HashMap<String, Object>());
    }

    private void deleteAccount(Account acct) throws ServiceException {
        if (acct == null) {
            return;
        }
        getProv().deleteAccount(acct.getId());
    }

    private Domain getDomain(String name) throws ServiceException {
        return getProv().get(Key.DomainBy.name, name);
    }

    private Domain createDomain(String domainName) throws ServiceException {
        return getProv().createDomain(domainName, new HashMap<String, Object>());
    }

    private void deleteDomain(Domain domain) throws ServiceException {
        if (domain == null) {
            return;
        }
        getProv().deleteDomain(domain.getId());
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
        getProv().modifyAttrs(acct, attrs);
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
        getProv().modifyAttrs(domain, attrs);
    }

    private static String baseDomainName() {
        return TestNginxLookupExtension.class.getName().toLowerCase();
    }

    private static String getDomainName(String domainName) {
        return domainName + "." + baseDomainName();
    }

    @Before
    public void setUp() throws Exception {
        InetAddress IP = InetAddress.getLocalHost();
        MY_IP_ADDRESS = IP.getHostAddress();
        DEFAULT_DOMAIN = AccountTestUtil.getDomain();
        USER = testInfo.getMethodName() + "1";
        QUSER = USER + "@" +DEFAULT_DOMAIN;
        tearDown();
    }

    @After
    public void tearDown() throws Exception {
        TestUtil.deleteAccountIfExists(USER);
        deleteAccount(externalRouteAccount);
        deleteDomain(externalRouteDomain);
        externalRouteAccount = null;
        externalRouteDomain = null;
    }

    @Test
    public void imap() throws Exception {
        TestUtil.createAccount(QUSER);
        LookupData lookupData = new LookupData(AuthMethod.plain, QUSER, PASSWORD, AuthProtocol.imap);
        RespHeaders respHdrs = senRequest(lookupData);
        String[] ports = {IMAP_PORT, IMAP_DAEMON_PORT};
        respHdrs.assertBasic(QUSER, MY_IP_ADDRESS, ports);
    }

    @Test
    public void imapssl() throws Exception {
        TestUtil.createAccount(QUSER);
        LookupData lookupData = new LookupData(AuthMethod.plain, QUSER, PASSWORD, AuthProtocol.imapssl);
        RespHeaders respHdrs = senRequest(lookupData);
        String[] ports = {IMAP_SSL_PORT, IMAP_DAEMON_SSL_PORT};
        respHdrs.assertBasic(QUSER, MY_IP_ADDRESS, ports);
    }

    @Test
    public void pop3() throws Exception {
        TestUtil.createAccount(QUSER);
        LookupData lookupData = new LookupData(AuthMethod.plain, QUSER, PASSWORD, AuthProtocol.pop3);
        RespHeaders respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(QUSER, MY_IP_ADDRESS, POP3_PORT);
    }

    @Test
    public void pop3ssl() throws Exception {
        TestUtil.createAccount(QUSER);
        LookupData lookupData = new LookupData(AuthMethod.plain, QUSER, PASSWORD, AuthProtocol.pop3ssl);
        RespHeaders respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(QUSER, MY_IP_ADDRESS, POP3_SSL_PORT);
    }

    @Test
    public void http() throws Exception {
        TestUtil.createAccount(USER);
        LookupData lookupData = new LookupData(AuthMethod.plain, QUSER, PASSWORD, AuthProtocol.http);
        RespHeaders respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(QUSER, MY_IP_ADDRESS, HTTP_PORT);
    }

    @Test
    public void externalRouteOnAccountUseRouteOnAccount() throws Exception {
        String user = "user";
        String domainName = getDomainName("account.account.externalroute");
        String quser = user + "@" + domainName;

        externalRouteAccount = createAccount(user, domainName);
        externalRouteDomain = getDomain(domainName);

        setupExternalRoute(externalRouteAccount, true, "1", "2", "3", "4");

        LookupData lookupData;
        RespHeaders respHdrs;

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.pop3);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "1");

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.pop3ssl);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "2");

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.imap);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "3");

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.imapssl);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "4");
    }

    @Test
    public void externalRouteOnAccountUseRouteOnAccountUseRouteOnDomain() throws Exception {
        String user = "user";
        String domainName = getDomainName("account.domain.externalroute");
        String quser = user + "@" + domainName;

        externalRouteAccount = createAccount(user, domainName);
        setupExternalRoute(externalRouteAccount, true, "", "", "", "");

        externalRouteDomain = getDomain(domainName);
        setupExternalRoute(externalRouteDomain, true, null, "5", "6", "7", "8");

        LookupData lookupData;
        RespHeaders respHdrs;

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.pop3);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "5");

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.pop3ssl);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "6");

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.imap);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "7");

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.imapssl);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "8");
    }

    @Test
    public void externalRouteOnDomainUseRouteOnAccountUseRouteOnAccount() throws Exception {
        String user = "user";
        String domainName = getDomainName("domain.account.externalroute");
        String quser = user + "@" + domainName;

        externalRouteAccount = createAccount(user, domainName);
        setupExternalRoute(externalRouteAccount, null, "1", "2", "3", "4");

        externalRouteDomain = getDomain(domainName);
        setupExternalRoute(externalRouteDomain, true, null, "5", "6", "7", "8");

        LookupData lookupData;
        RespHeaders respHdrs;

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.pop3);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "1");

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.pop3ssl);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "2");

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.imap);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "3");

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.imapssl);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "4");
    }

    @Test
    public void externalRouteOnDomainUseRouteOnAccountUseRouteOnDomain() throws Exception {
        String user = "user";
        String domainName = getDomainName("domain.domain.externalroute");
        String quser = user + "@" + domainName;

        externalRouteAccount = createAccount(user, domainName);
        setupExternalRoute(externalRouteAccount, null, "", "", "", "");

        externalRouteDomain = getDomain(domainName);
        setupExternalRoute(externalRouteDomain, true, null, "5", "6", "7", "8");

        LookupData lookupData;
        RespHeaders respHdrs;

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.pop3);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "5");

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.pop3ssl);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "6");

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.imap);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "7");

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.imapssl);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "8");
    }

    @Test
    public void externalRouteOnDomainIfAccountNoExistUseRouteOnAccountUseRouteOnDomain() throws Exception {
        String user = "user";
        String domainName = getDomainName("domain.domain.acountNotExist.externalroute");
        String quser = user + "@" + domainName;

        externalRouteDomain = createDomain(domainName);
        setupExternalRoute(externalRouteDomain, true, true, "5", "6", "7", "8");

        LookupData lookupData;
        RespHeaders respHdrs;

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.pop3);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "5");

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.pop3ssl);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "6");

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.imap);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "7");

        lookupData = new LookupData(AuthMethod.plain, quser, PASSWORD, AuthProtocol.imapssl);
        respHdrs = senRequest(lookupData);
        respHdrs.assertBasic(quser, LOCALHOST_IP, "8");
    }
}
