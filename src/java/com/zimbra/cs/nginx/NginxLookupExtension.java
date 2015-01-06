/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014 Zimbra, Inc.
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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;

import com.google.common.annotations.VisibleForTesting;
import com.zimbra.common.account.Key.AccountBy;
import com.zimbra.common.localconfig.LC;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.Constants;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.AuthToken;
import com.zimbra.cs.account.AuthTokenException;
import com.zimbra.cs.account.CacheExtension;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.extension.ExtensionDispatcherServlet;
import com.zimbra.cs.extension.ExtensionException;
import com.zimbra.cs.extension.ZimbraExtension;
import com.zimbra.qa.unittest.TestNginxLookup;
import com.zimbra.qa.unittest.ZimbraSuite;

public class NginxLookupExtension implements ZimbraExtension {
    protected NginxLookupHandler handler;

    public static final String NAME = "nginx-lookup";

    static NginxLookupCache<DomainInfo> sDomainNameByVirtualIpCache =
        new NginxLookupCache<DomainInfo>(
                LC.ldap_cache_reverseproxylookup_domain_maxsize.intValue(),
                LC.ldap_cache_reverseproxylookup_domain_maxage.intValue() * Constants.MILLIS_PER_MINUTE);

    static NginxLookupCache<DomainExternalRouteInfo> sDomainExternalRouteByDomainNameCache =
        new NginxLookupCache<DomainExternalRouteInfo>(
                LC.ldap_cache_reverseproxylookup_domain_maxsize.intValue(),
                LC.ldap_cache_reverseproxylookup_domain_maxage.intValue() * Constants.MILLIS_PER_MINUTE);


    static NginxLookupCache<ServerInfo> sServerCache =
        new NginxLookupCache<ServerInfo>(
                LC.ldap_cache_reverseproxylookup_server_maxsize.intValue(),
                LC.ldap_cache_reverseproxylookup_server_maxage.intValue() * Constants.MILLIS_PER_MINUTE);


    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public void init() throws ExtensionException, ServiceException {
        handler = new NginxLookupHandler();
        ExtensionDispatcherServlet.register(this, handler);
        CacheExtension.register("reverseproxylookup", new ReverseProxyCache());
        try {
            ZimbraSuite.addTest(TestNginxLookup.class);
        } catch (NoClassDefFoundError e) {
            // Expected in production, because JUnit is not available.
            ZimbraLog.test.debug("Unable to load TestNginxLookup unit tests.", e);
        }
    }

    @Override
    public void destroy() {
        ExtensionDispatcherServlet.unregister(this);
    }

    @VisibleForTesting
    public void clearCache() {
        handler.clearCache();
    }

    @SuppressWarnings("serial")
    public static class NginxLookupException extends Exception {
        public NginxLookupException(String msg) {
            super(msg);
        }

        public NginxLookupException(Throwable cause) {
            super(cause);
            ZimbraLog.nginxlookup.debug("", cause);
        }

        public NginxLookupException(String msg, Throwable cause) {
            super(msg, cause);
            ZimbraLog.nginxlookup.debug("", cause);
        }
    }

    public static class EntryNotFoundException extends NginxLookupException {
        public EntryNotFoundException(String msg) {
            super(msg);
        }
    }

    static class ReverseProxyCache extends CacheExtension {

        @Override
        public void flushCache() throws ServiceException {
            sDomainNameByVirtualIpCache.clear();
            sDomainExternalRouteByDomainNameCache.clear();
            sServerCache.clear();
        }
    }

    static class NginxLookupRequest {
        String user;
        String cuser;
        String pass;
        String proto;
        String authMethod;
        String clientIp;
        String serverIp;
        String serverHost;
        String principal;
        int loginAttempt;
        boolean isZimbraAdmin;
        String adminUser;
        String adminPass;
        HttpServletRequest  httpReq;

        public NginxLookupRequest() {}

        public NginxLookupRequest(String user, String pass, String authMethod, String proto) {
            this.user = user;
            this.pass = pass;
            this.authMethod = authMethod;
            this.proto = proto;
        }
    }

    static class NginxLookupResponse {
        HttpServletResponse httpResp;

        public NginxLookupResponse() {
            httpResp = new MockHttpServletResponse();
        }

        public NginxLookupResponse(HttpServletResponse httpResp) {
            this.httpResp = httpResp;
        }
    }

    private static void test(String user, String pass, String serverIp) {
        String url = "http://localhost:7072/service/extension/nginx-lookup";

        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod(url);

        method.setRequestHeader("Host", "localhost");
        method.setRequestHeader(NginxLookupHandler.AUTH_METHOD, "plain");
        method.setRequestHeader(NginxLookupHandler.AUTH_USER, user);
        method.setRequestHeader(NginxLookupHandler.AUTH_PASS, pass);
        method.setRequestHeader(NginxLookupHandler.AUTH_PROTOCOL, "imap");
        method.setRequestHeader(NginxLookupHandler.AUTH_LOGIN_ATTEMPT, "1");
        method.setRequestHeader(NginxLookupHandler.CLIENT_IP, "127.0.0.1");

        if (serverIp != null)
            method.setRequestHeader(NginxLookupHandler.SERVER_IP, serverIp);

        try {
            int statusCode = client.executeMethod(method);

            Header authStatus = method.getResponseHeader(NginxLookupHandler.AUTH_STATUS);
            Header authServer = method.getResponseHeader(NginxLookupHandler.AUTH_SERVER);
            Header authPort = method.getResponseHeader(NginxLookupHandler.AUTH_PORT);
            Header authUser = method.getResponseHeader(NginxLookupHandler.AUTH_USER);
            Header authWait = method.getResponseHeader(NginxLookupHandler.AUTH_WAIT);

            System.out.println("===== user:" + user + " pass: " + pass + " serverIp:" + serverIp);

            System.out.println(NginxLookupHandler.AUTH_STATUS + ": " + ((authStatus==null)?"(null)":authStatus.getValue()));
            System.out.println(NginxLookupHandler.AUTH_SERVER + ": " + ((authServer==null)?"(null)":authServer.getValue()));
            System.out.println(NginxLookupHandler.AUTH_PORT + ": " + ((authPort==null)?"(null)":authPort.getValue()));
            System.out.println(NginxLookupHandler.AUTH_USER + ": " + ((authUser==null)?"(null)":authUser.getValue()));
            System.out.println(NginxLookupHandler.AUTH_WAIT + ": " + ((authWait==null)?"(null)":authWait.getValue()));
            System.out.println();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void doTest(String h_AUTH_METHOD,
                               String h_AUTH_USER,
                               String h_AUTH_PASS,
                               String h_AUTH_PROTOCOL,
                               String h_AUTH_LOGIN_ATTEMPT,
                               String h_CLIENT_IP,
                               String h_SERVER_IP,
                               String h_SERVER_HOST,
                               String h_AUTH_ID,
                               String h_AUTH_ADMIN_USER,
                               String h_AUTH_ADMIN_PASS,
                               boolean expectedOK) {
        String url = "http://localhost:7072/service/extension/nginx-lookup";

        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod(url);

        method.setRequestHeader("Host", "localhost");
        if (h_AUTH_METHOD != null)
            method.setRequestHeader(NginxLookupHandler.AUTH_METHOD, h_AUTH_METHOD);
        if (h_AUTH_USER != null)
            method.setRequestHeader(NginxLookupHandler.AUTH_USER, h_AUTH_USER);
        if (h_AUTH_PASS != null)
            method.setRequestHeader(NginxLookupHandler.AUTH_PASS, h_AUTH_PASS);
        if (h_AUTH_PROTOCOL != null)
            method.setRequestHeader(NginxLookupHandler.AUTH_PROTOCOL, h_AUTH_PROTOCOL);
        if (h_AUTH_LOGIN_ATTEMPT != null)
            method.setRequestHeader(NginxLookupHandler.AUTH_LOGIN_ATTEMPT, h_AUTH_LOGIN_ATTEMPT);
        if (h_CLIENT_IP != null)
            method.setRequestHeader(NginxLookupHandler.CLIENT_IP, h_CLIENT_IP);
        if (h_SERVER_IP != null)
            method.setRequestHeader(NginxLookupHandler.SERVER_IP, h_SERVER_IP);
        if (h_SERVER_HOST != null)
            method.setRequestHeader(NginxLookupHandler.SERVER_HOST, h_SERVER_HOST);
        if (h_AUTH_ID != null)
            method.setRequestHeader(NginxLookupHandler.AUTH_ID, h_AUTH_ID);
        if (h_AUTH_ADMIN_USER != null)
            method.setRequestHeader(NginxLookupHandler.AUTH_ADMIN_USER, h_AUTH_ADMIN_USER);
        if (h_AUTH_ADMIN_PASS != null)
            method.setRequestHeader(NginxLookupHandler.AUTH_ADMIN_PASS, h_AUTH_ADMIN_PASS);


        System.out.println("Request headers:");
        for (Header header : method.getRequestHeaders()) {
            System.out.print("    " + header.toString());
        }
        System.out.println();

        boolean isOK = false;
        try {
            int statusCode = client.executeMethod(method);

            System.out.println("Response headers:");
            for (Header header : method.getResponseHeaders()) {
                if (header.getName().equals(NginxLookupHandler.AUTH_STATUS) &&
                    "OK".equals(header.getValue()))
                    isOK = true;

                System.out.print("    " + header.toString());

                if (header.getName().equals(NginxLookupHandler.AUTH_PASS)) {
                    try {
                        AuthToken at = AuthToken.getAuthToken(header.getValue());
                        String acctId = at.getAccountId();
                        String acctName = Provisioning.getInstance().get(AccountBy.id, acctId).getName();
                        System.out.println("        (Authed account: id=" + at.getAccountId() + ", name=" + acctName);
                    } catch (ServiceException e) {
                        System.out.println("        (Not a valid auth token)");
                    } catch (AuthTokenException e)  {
                        System.out.println("        (Not a valid auth token)");
                    }
                }
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println();
        if (expectedOK == isOK)
            System.out.println("succeeded");
        else
            System.out.println("failed");

        System.out.println("\n=========================================\n");
    }

    public static void main(String args[]) {
        /*
        test("user1@phoebe.mac", "test123", null);
        test("imapappendthunderbird1190418967@qa07.liquidsys.com/kk", "test123", null);
        test("user1", "test123", null);
        test("user2", "test123", "127.0.0.1");
        test("user3", "test123", "127.0.0.2");
        test("alias@phoebe.mac", "test123", null);  // zmprov aaa  user1@phoebe.mac alias@phoebe.mac
        test("user1@alias.com", "test123", null);   // zmprov cad alias.com phoebe.mac
        */

        /*
         * zmprov md phoebe.mac zimbraAuthKerberos5Realm ZIMBRA.COM zimbraVirtualIPAddress 13.12.11.10
         * zmprov mcf zimbraReverseProxyAdminIPAddress 13.12.11.10
         *
         * for Comcast test
         * zmprov md comcast.net zimbraAuthKerberos5Realm ZIMBRA.COM zimbraVirtualIPAddress 13.12.11.10
         */

        //     AUTH_METHOD  AUTH_USER                  AUTH_PASS  AUTH_PROTOCOL  AUTH_LOGIN_ATTEMPT  CLIENT_IP      SERVER_IP      SERVER_HOST  AUTH_ID                      AUTH_ADMIN_USER            AUTH_ADMIN_PASS
    //  doTest("plain",     "user1",                  "test123",  "imap",        "1",                "10.11.12.13", "127.0.0.1",   null,        null,                        null,                      null,            true);
        /*
        doTest("gssapi",    "user1",                   null,      "imap",        "1",                "10.11.12.13", "13.12.11.10", null,        "user1@ZIMBRA.COM",          "zmnginx",                 "zimbra",       true);
        doTest("gssapi",    "user1@phoebe.mac",        null,      "imap",        "1",                "10.11.12.13", "13.12.11.10", null,        "user1@ZIMBRA.COM",          "zmnginx",                 "zimbra",       true);
        doTest("gssapi",    "user1@ZIMBRA.COM",        null,      "imap",        "1",                "10.11.12.13", "13.12.11.10", null,        "user1@ZIMBRA.COM",          "zmnginx",                 "zimbra",       true);
        doTest("gssapi",    "user2",                   null,      "imap",        "1",                "10.11.12.13", "13.12.11.10", null,        "user1@ZIMBRA.COM",          "zmnginx",                 "zimbra",       false);
        doTest("gssapi",    "family-child1-visible",   null,      "imap",        "1",                "10.11.12.13", "13.12.11.10", null,        "family-parent@ZIMBRA.COM",  "zmnginx",                 "zimbra",       true);
        doTest("gssapi",    "user1",                   null,      "imap",        "1",                "10.11.12.13", "13.12.11.10", null,        "user1@ZIMBRA.COM",          "zmnginxbogus",            "zimbra",       false);
        */

        /*
        // comcast test
        doTest("gssapi",    "combo",                   null,      "imap",        "1",                "10.11.12.13", "13.12.11.10", null,        "combo@ZIMBRA.COM",          "zmnginx",                 "zimbra",       false);
        doTest("gssapi",    "combo@comcast.net",        null,      "imap",        "1",                "10.11.12.13", "13.12.11.10", null,        "combo@ZIMBRA.COM",          "zmnginx",                 "zimbra",      false);
        doTest("gssapi",    "combo@ZIMBRA.COM",        null,      "imap",        "1",                "10.11.12.13", "13.12.11.10", null,        "combo@ZIMBRA.COM",          "zmnginx",                 "zimbra",       false);
        doTest("gssapi",    "user2",                   null,      "imap",        "1",                "10.11.12.13", "13.12.11.10", null,        "combo@ZIMBRA.COM",          "zmnginx",                 "zimbra",       false);
        doTest("gssapi",    "combo",                   null,      "imap",        "1",                "10.11.12.13", "13.12.11.10", null,        "combo@ZIMBRA.COM",          "zmnginxbogus",            "zimbra",       false);
        */

        /*
        doTest("plain",     "user1",                   null,      "imap",        "1",                "10.11.12.13", "13.12.11.10", null,        null,                        null,                      null,            true);
        doTest("plain",     "user1",                   null,      "imapssl",     "1",                "10.11.12.13", "13.12.11.10", null,        null,                        null,                      null,            true);
        doTest("plain",     "user1",                   null,      "pop3",        "1",                "10.11.12.13", "13.12.11.10", null,        null,                        null,                      null,            true);
        doTest("plain",     "user1",                   null,      "pop3ssl",     "1",                "10.11.12.13", "13.12.11.10", null,        null,                        null,                      null,            true);
        */


        /*
         *
If they are using nginx proxy, there is a hack, and it only works if they turn *off* memcached.

The steps are:
1. Set virtual IP on the domain to the nginx incoming interface IP
       zmprov md domain.com zimbraVirtualIPAddress {nginx-IP}

2. Set account's zimbraForeignPrinicipal to user%domain.com@domain.com.  This need to be done on all accounts.
       zmprov ma user@domain.com zimbraForeignPrincipal user%domain.com@domain.com

3. Set the host query to include the foreign principal
       zmprov mcf zimbraReverseProxyMailHostQuery '(|(zimbraMailDeliveryAddress=${USER})(zimbraMailAlias=${USER})(zimbraId=${USER})(zimbraForeignPrincipal=${USER}))'

4. Set the addr that contains the right user name to zimbraMailDeliveryAddress.  This will return the correct name user@domain.com to nginx in the Auth-User http header, and then the right name will be passed by nginx to the real IMAP/POP server.
       zmprov mcf zimbraReverseProxyUserNameAttribute zimbraMailDeliveryAddress

         */
        // doTest("plain",     "user1%phoebe.mac",        "test123",  "imap",       "1",                "10.11.12.13", "127.0.0.1",   null,        null,                        null,                      null,            true);
   }
}
