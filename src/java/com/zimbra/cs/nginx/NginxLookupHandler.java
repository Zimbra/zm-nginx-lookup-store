package com.zimbra.cs.nginx;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.net.util.SubnetUtils;
import org.apache.commons.net.util.SubnetUtils.SubnetInfo;

import com.google.common.annotations.VisibleForTesting;
import com.zimbra.common.account.Key;
import com.zimbra.common.account.Key.AccountBy;
import com.zimbra.common.account.ProvisioningConstants;
import com.zimbra.common.localconfig.DebugConfig;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.servicelocator.Selector;
import com.zimbra.common.servicelocator.ServiceLocator;
import com.zimbra.common.servicelocator.ZimbraServiceNames;
import com.zimbra.common.util.StringUtil;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.AccessManager;
import com.zimbra.cs.account.Account;
import com.zimbra.cs.account.AuthTokenException;
import com.zimbra.cs.account.Config;
import com.zimbra.cs.account.Domain;
import com.zimbra.cs.account.Provisioning;
import com.zimbra.cs.account.Server;
import com.zimbra.cs.account.auth.AuthContext;
import com.zimbra.cs.account.auth.AuthMechanism;
import com.zimbra.cs.account.ldap.LdapProv;
import com.zimbra.cs.extension.ExtensionException;
import com.zimbra.cs.extension.ExtensionHttpHandler;
import com.zimbra.cs.extension.ZimbraExtension;
import com.zimbra.cs.ldap.ILdapContext;
import com.zimbra.cs.ldap.ZLdapFilter;
import com.zimbra.cs.ldap.ZLdapFilterFactory;
import com.zimbra.cs.ldap.ZLdapFilterFactory.FilterId;
import com.zimbra.cs.nginx.LdapLookup.SearchDirResult;
import com.zimbra.cs.nginx.NginxLookupExtension.EntryNotFoundException;
import com.zimbra.cs.nginx.NginxLookupExtension.NginxLookupException;
import com.zimbra.cs.nginx.NginxLookupExtension.NginxLookupRequest;
import com.zimbra.cs.nginx.NginxLookupExtension.NginxLookupResponse;
import com.zimbra.cs.service.AuthProvider;
import com.zimbra.cs.service.authenticator.ClientCertAuthenticator;
import com.zimbra.cs.util.IPUtil;
import com.zimbra.cs.util.Zimbra;

public class NginxLookupHandler extends ExtensionHttpHandler {
        /* req headers */
        public static final String AUTH_METHOD        = "Auth-Method";
        public static final String AUTH_USER          = "Auth-User";
        public static final String AUTH_PASS          = "Auth-Pass";
        public static final String AUTH_PROTOCOL      = "Auth-Protocol";
        public static final String AUTH_ZIMBRA_ADMIN  = "Auth-Zimbra-Admin";
        public static final String AUTH_LOGIN_ATTEMPT = "Auth-Login-Attempt";
        public static final String CLIENT_IP          = "Client-IP";
        public static final String SERVER_IP          = "X-Proxy-IP";
        public static final String SERVER_HOST        = "X-Proxy-Host";
        public static final String AUTH_ID            = "Auth-Id";
        public static final String AUTH_ADMIN_USER    = "Auth-Admin-User";
        public static final String AUTH_ADMIN_PASS    = "Auth-Admin-Pass";

        /* resp headers */
        public static final String AUTH_STATUS      = "Auth-Status";
        public static final String AUTH_SERVER      = "Auth-Server";
        public static final String AUTH_PORT        = "Auth-Port";
        public static final String AUTH_WAIT        = "Auth-Wait";
        public static final String AUTH_CACHE_ALIAS = "Auth-Cache-Alias";

        public static final long DEFAULT_WAIT_INTERVAL = 10;

        /* Generic Error Message for failure */
        public static final String ERRMSG = "login failed";
        public static final String ACCESS_DENIED_ERRMSG = "is not allowed on this domain";

        /* protocols */
        public static final String POP3     = "pop3";
        public static final String POP3_SSL = "pop3ssl";
        public static final String IMAP     = "imap";
        public static final String IMAP_SSL = "imapssl";
        public static final String HTTP     = "http";
        public static final String HTTP_SSL = "httpssl";

        /* auth methods */
        public static final String AUTHMETH_PLAIN = "plain";
        public static final String AUTHMETH_OTHER = "other";
        public static final String AUTHMETH_ZIMBRAID = "zimbraId";
        public static final String AUTHMETH_GSSAPI = "gssapi";
        public static final String AUTHMETH_CERTAUTH = "certauth";

        protected LdapProv prov;
        protected LdapLookup ldapLookup;
        protected ServiceLocator serviceLocator;

        @Override
        public boolean hideFromDefaultPorts() {
            return true;
        }

        public NginxLookupHandler() throws ExtensionException {
            try {
                prov = LdapProv.getInst();
                ldapLookup = new LdapProvLdapLookup(prov);
                serviceLocator = Zimbra.getAppContext().getBean(ServiceLocator.class);
            } catch (ServiceException e) {
                throw new ExtensionException("unable to initialize nginx lookup servlet", e);
            }
        }

        public NginxLookupHandler(LdapProv ldapProv) throws ExtensionException {
            prov = ldapProv;
            ldapLookup = new LdapProvLdapLookup(prov);
            serviceLocator = Zimbra.getAppContext().getBean(ServiceLocator.class);
        }

        @Override
        public void init(ZimbraExtension ext) throws ServiceException {
            super.init(ext);
        }

        public void setServiceLocator(ServiceLocator serviceLocator) {
            this.serviceLocator = serviceLocator;
        }

        @VisibleForTesting
        void clearCache() {
            NginxLookupExtension.sDomainNameByVirtualIpCache.clear();
            NginxLookupExtension.sDomainExternalRouteByDomainNameCache.clear();
        }

        private String[] getUserSC(Config config) {
            String attr;
            ArrayList<String> attrs = new ArrayList<String>();

            attr = config.getAttr(Provisioning.A_zimbraReverseProxyMailHostAttribute);
            if (attr != null)
                attrs.add(attr);
            attr = config.getAttr(Provisioning.A_zimbraReverseProxyUserNameAttribute);
            if (attr != null)
                attrs.add(attr);
            attrs.add(Provisioning.A_zimbraReverseProxyUseExternalRoute);
            attrs.add(Provisioning.A_zimbraExternalPop3Port);
            attrs.add(Provisioning.A_zimbraExternalPop3SSLPort);
            attrs.add(Provisioning.A_zimbraExternalImapPort);
            attrs.add(Provisioning.A_zimbraExternalImapSSLPort);
            attrs.add(Provisioning.A_zimbraExternalPop3Hostname);
            attrs.add(Provisioning.A_zimbraExternalPop3SSLHostname);
            attrs.add(Provisioning.A_zimbraExternalImapHostname);
            attrs.add(Provisioning.A_zimbraExternalImapSSLHostname);

            return attrs.toArray(new String[attrs.size()]);
        }

        private String[] getServerSC(Config config) {
            String attr;
            ArrayList<String> attrs = new ArrayList<String>();

            attr = config.getAttr(Provisioning.A_zimbraReverseProxyPop3PortAttribute);
            if (attr != null)
                attrs.add(attr);
            attr = config.getAttr(Provisioning.A_zimbraReverseProxyPop3SSLPortAttribute);
            if (attr != null)
                attrs.add(attr);
            attr = config.getAttr(Provisioning.A_zimbraReverseProxyImapPortAttribute);
            if (attr != null)
                attrs.add(attr);
            attr = config.getAttr(Provisioning.A_zimbraReverseProxyImapSSLPortAttribute);
            if (attr != null)
                attrs.add(attr);
            attr = config.getAttr(Provisioning.A_zimbraReverseProxyHttpPortAttribute);
            if (attr != null)
                attrs.add(attr);
            attr = config.getAttr(Provisioning.A_zimbraReverseProxyHttpSSLPortAttribute);
            if (attr != null)
                attrs.add(attr);

            return attrs.toArray(new String[attrs.size()]);
        }

        private String[] getDomainSC(Config config) {
            String attr;
            ArrayList<String> attrs = new ArrayList<String>();

            attr = config.getAttr(Provisioning.A_zimbraReverseProxyDomainNameAttribute);
            if (attr != null)
                attrs.add(attr);

            attrs.add(Provisioning.A_zimbraReverseProxyUseExternalRoute);
            attrs.add(Provisioning.A_zimbraReverseProxyUseExternalRouteIfAccountNotExist);
            attrs.add(Provisioning.A_zimbraReverseProxyExternalRouteIncludeOriginalAuthusername);
            attrs.add(Provisioning.A_zimbraExternalPop3Port);
            attrs.add(Provisioning.A_zimbraExternalPop3SSLPort);
            attrs.add(Provisioning.A_zimbraExternalImapPort);
            attrs.add(Provisioning.A_zimbraExternalImapSSLPort);
            attrs.add(Provisioning.A_zimbraExternalPop3Hostname);
            attrs.add(Provisioning.A_zimbraExternalPop3SSLHostname);
            attrs.add(Provisioning.A_zimbraExternalImapHostname);
            attrs.add(Provisioning.A_zimbraExternalImapSSLHostname);

            return attrs.toArray(new String[attrs.size()]);
        }

        protected static String getServiceIDForProto(String proto) {
            if ("http".equals(proto)) {
                return ZimbraServiceNames.MAILSTORE;
            } else if ("httpssl".equals(proto)) {
                return ZimbraServiceNames.MAILSTORE;
            } else if ("imap".equals(proto)) {
                return ZimbraServiceNames.IMAP;
            } else if ("imapssl".equals(proto)) {
                return ZimbraServiceNames.IMAP;
            } else if ("pop3".equals(proto)) {
                return ZimbraServiceNames.POP;
            } else if ("pop3ssl".equals(proto)) {
                return ZimbraServiceNames.POP;
            } else {
                return null;
            }
        }

        @Override
        public void doGet(HttpServletRequest httpReq, HttpServletResponse httpRes) throws IOException, ServletException {
            try {
                NginxLookupRequest req = checkRequest(httpReq);
                req.httpReq  = httpReq;
                NginxLookupResponse res = new NginxLookupResponse(httpRes);
                search(req, res);
            } catch (NginxLookupException ex) {
                sendError(httpRes, ex.getMessage());
            }
        }

        /**
         * Parse the HTTP request headers and construct the NginxLookupRequest object
         * @param httpReq The HTTP Servlet Request object
         * @return    NginxLookupRequest object containing details of the lookup request
         * @throws NginxLookupException
         */
        private NginxLookupRequest checkRequest(HttpServletRequest httpReq) throws NginxLookupException
        {
            /* Build the request object and extract the various request headers */

            NginxLookupRequest req = new NginxLookupRequest();
            NginxLookupResponse res = new NginxLookupResponse();

            /* NGINX will never pass any suffixes to the lookup servlet
               So no need to look for /tb|/wm|/ni in req.user
             */
            try { //bug 51672, username and password need unescape
                req.user     = unescapeAuthUserAndPass(httpReq.getHeader(AUTH_USER)); /* User whose route is to be looked up */
                req.pass     = unescapeAuthUserAndPass(httpReq.getHeader(AUTH_PASS)); /* Password */
            } catch (IllegalArgumentException e) {
                throw new NginxLookupException(e);
            }
            req.proto           = httpReq.getHeader(AUTH_PROTOCOL);         /* Protocol {imap|imaps|pop3|pop3s|http} */
            req.authMethod      = httpReq.getHeader(AUTH_METHOD);           /* Auth Method {passwd|plain|gssapi|other|zimbraId} */
            req.cuser           = httpReq.getHeader(AUTH_ID);               /* (GSSAPI) Authenticating Principal */
            req.adminUser       = httpReq.getHeader(AUTH_ADMIN_USER);       /* auth admin user, required for GSSAPI */
            req.adminPass       = httpReq.getHeader(AUTH_ADMIN_PASS);       /* auth admin password, , required for GSSAPI */
            req.clientIp        = httpReq.getHeader(CLIENT_IP);             /* Upstream Client IP */
            req.serverIp        = httpReq.getHeader(SERVER_IP);             /* Incoming Proxy Interface IP */
            req.serverHost      = httpReq.getHeader(SERVER_HOST);           /* (HTTP) Host header */
            req.loginAttempt    = 1;
            req.isZimbraAdmin   = false;


            /* Complain if any required fields are missing */

            if (req.user == null)
                throw new NginxLookupException("missing header field " + AUTH_USER);
            if (req.authMethod == null)
                throw new NginxLookupException("missing header field " + AUTH_METHOD);
            if (req.proto == null)
                throw new NginxLookupException("missing header field " + AUTH_PROTOCOL);
            if (req.authMethod.equalsIgnoreCase(AUTHMETH_GSSAPI)) {
                if (req.cuser == null)
                    throw new NginxLookupException("(GSSAPI) missing header field " + AUTH_ID);

                if (req.adminUser == null)
                    throw new NginxLookupException("(GSSAPI) missing header field " + AUTH_ADMIN_USER);

                if (req.adminPass == null)
                    throw new NginxLookupException("(GSSAPI) missing header field " + AUTH_ADMIN_PASS);

                if (req.serverIp == null)
                    throw new NginxLookupException("(GSSAPI) missing header field " + SERVER_IP);
            } else if (req.authMethod.equalsIgnoreCase(AUTHMETH_CERTAUTH)) {
                if (req.adminUser == null)
                    throw new NginxLookupException("(CERTAUTH) missing header field " + AUTH_ADMIN_USER);

                if (req.adminPass == null)
                    throw new NginxLookupException("(CERTAUTH) missing header field " + AUTH_ADMIN_PASS);

                if (req.serverIp == null)
                    throw new NginxLookupException("(CERTAUTH) missing header field " + SERVER_IP);

                req.user = unifyDNFormat(req.user);
            }

            if (req.pass == null)   /* We should not complain on null password */
                req.pass = "";

            String val = httpReq.getHeader(AUTH_LOGIN_ATTEMPT);
            if (val != null) {
                try {
                    req.loginAttempt = Integer.parseInt(val);
                } catch (NumberFormatException e) {
                }
            }

            String isZimbraAdmin = httpReq.getHeader(AUTH_ZIMBRA_ADMIN);
            if (isZimbraAdmin != null) {
                req.isZimbraAdmin = Boolean.parseBoolean (isZimbraAdmin);
            }

            return req;
        }

        /**
         * The DN returned by nginx looks like:
         * /C=US/ST=California/L=Saratoga/O=Zimbra/OU=Engineering/CN=user one/emailAddress=user1@u10
         * This method changes the separator to ",", trim the first "/" and make
         * "emailAddress" to "EMAILADDRESS"
         */
        private static String unifyDNFormat(String dn) {
        	if (dn.startsWith("/")) {
        		dn = dn.substring(1); //trim the first "/"
        	}

        	dn = dn.replace("/", ",");
        	dn = dn.replace("emailAddress", "EMAILADDRESS");
        	return dn;
        }

        /**
         * Unescape all the '%xy' combinations in <code>src</code> to their
         * normal form, where 'xy' must be a valid hex value.
         * @param src the string to be unescaped
         * @return the escape result
         * @throws IllegalArgumentException throw when trailing escape (%)
         *         pattern is incomplete
         */
        private static String unescapeAuthUserAndPass(String src) {
            if (src == null) {
                return null;
            }

            int len = src.length();
            StringBuffer sb = new StringBuffer(src.length());
            int last = 0;
            int pos = src.indexOf("%");
            while (true) {
                if (pos == -1) {
                    sb.append(src.substring(last, len));
                    break;
                } else {
                    sb.append(src.substring(last, pos));
                    if (pos >= len - 2)
                        throw new IllegalArgumentException(
                            "Incomplete trailing escape (%) pattern");
                    char d1 = src.charAt(pos + 1);
                    char d2 = src.charAt(pos + 2);
                    //judge valid hex value
                    if (!(((d1 >= '0' && d1 <= '9') || (d1 >= 'A' && d1 <= 'F') || (d1 >= 'a' && d1 <= 'f')) &&
                          ((d2 >= '0' && d2 <= '9') || (d2 >= 'A' && d2 <= 'F') || (d2 >= 'a' && d2 <= 'f')))) {
                        throw new IllegalArgumentException(
                        "Incomplete trailing escape (%) pattern");
                    }

                    char r = (char)((d1 - '0') * 16 + (d2 - '0'));
                    sb.append(r);
                    last = pos + 3;
                    pos = src.indexOf("%", last);
                }
            }

            return sb.toString();
        }
//        comment out unused method
//        private String getPortAttribute(NginxLookupRequest req) throws NginxLookupException
//        {
//            String proto = req.proto;
//
//            if (IMAP.equalsIgnoreCase(proto))
//                return Provisioning.A_zimbraReverseProxyImapPortAttribute;
//            else if (IMAP_SSL.equalsIgnoreCase(proto))
//                return Provisioning.A_zimbraReverseProxyImapSSLPortAttribute;
//            else if (POP3.equalsIgnoreCase(proto))
//                return Provisioning.A_zimbraReverseProxyPop3PortAttribute;
//            else if (POP3_SSL.equalsIgnoreCase(proto))
//                return Provisioning.A_zimbraReverseProxyPop3SSLPortAttribute;
//            else if (HTTP.equalsIgnoreCase(proto)) {
//                if (req.isZimbraAdmin) {
//                    return Provisioning.A_zimbraReverseProxyAdminPortAttribute;
//                } else {
//                    return Provisioning.A_zimbraReverseProxyHttpPortAttribute;
//                }
//            }
//            else
//                throw new NginxLookupException("unsupported protocol: "+proto);
//        }

        /**
         * verify that the request is from the legitimate nginx admin
         * @throws NginxLookupException
         */
        private void verifyNginxAdmin(Config config, NginxLookupRequest req) throws ServiceException, NginxLookupException {
            Set<String> allowedServerIPs = config.getMultiAttrSet(Provisioning.A_zimbraReverseProxyAdminIPAddress);
            if (!allowedServerIPs.contains(req.serverIp))
                throw new NginxLookupException(SERVER_IP + " " + req.serverIp + " is not allowed");

            Account adminAcct = prov.get(AccountBy.appAdminName, req.adminUser);
            if (adminAcct == null)
                throw new NginxLookupException("admin account " + req.adminUser + " not found");

            // must be global admin
            boolean isAdmin= adminAcct.getBooleanAttr(Provisioning.A_zimbraIsAdminAccount, false);
            if (!isAdmin)
                throw new NginxLookupException(req.adminUser + " is not an admin account");

            Map<String, Object> authCtxt = new HashMap<String, Object>();
            authCtxt.put(AuthContext.AC_ORIGINATING_CLIENT_IP, req.clientIp);
            authCtxt.put(AuthContext.AC_ACCOUNT_NAME_PASSEDIN, req.adminUser);
            AuthMechanism.doZimbraAuth(prov, null, adminAcct, req.adminPass, authCtxt);
        }

        /**
         * verify whether the account is an admin
         * account could be account name or account ID
         * @throws ServiceException
         */
        private void verifyAccountAdmin(String account, String authMethod)
                throws NginxLookupException, ServiceException {
            Account acct = null;
            if (authMethod.compareToIgnoreCase(AUTHMETH_ZIMBRAID) == 0) {
                acct = prov.get(AccountBy.id, account);
            } else {
                acct = prov.get(AccountBy.name, account);
            }

            if (acct == null) {
                throw new NginxLookupException("account " + account
                        + " not found");
            }

            boolean isAdmin = acct.getBooleanAttr(
                    Provisioning.A_zimbraIsAdminAccount, false);
            boolean isDelegatedAdmin = acct.getBooleanAttr(
                    Provisioning.A_zimbraIsDelegatedAdminAccount, false);
            if (!isAdmin && !isDelegatedAdmin) {
                throw new NginxLookupException("account " + account
                        + " is not admin or delegated admin");
            }
        }

        private String genAuthToken(Account authc, Config config, NginxLookupRequest req)
        throws ServiceException, NginxLookupException {
            verifyNginxAdmin(config, req);

            try {
                if (req.isZimbraAdmin) {
                    return AuthProvider.getAuthToken(authc, true).getEncoded();
                } else {
                    return AuthProvider.getAuthToken(authc).getEncoded();
                }
            } catch (AuthTokenException e) {
                throw new NginxLookupException("failed to generate auth token for " + authc.getName(), e);
            }
        }

        private String getDomainNameByServerIp(ILdapContext zlc, Config config, String serverIp, String unqualifiedName) {
            String domainName = null;

            DomainInfo domainInfo = NginxLookupExtension.sDomainNameByVirtualIpCache.get(serverIp);

            if (domainInfo == null) {
                try {
                    Map<String, Boolean> attrs = new HashMap<String, Boolean>();
                    attrs.put(Provisioning.A_zimbraReverseProxyDomainNameAttribute, true);

                    SearchDirResult sdr = ldapLookup.searchDirectory(
                            zlc,
                            getDomainSC(config),
                            config,
                            FilterId.NGINX_GET_DOMAIN_BY_SERVER_IP,
                            Provisioning.A_zimbraReverseProxyDomainNameQuery,
                            Provisioning.A_zimbraReverseProxyDomainNameSearchBase,
                            "IPADDR",
                            serverIp,
                            attrs,
                            null);

                    Map<String, String> vals = sdr.configuredAttrs;
                    domainName = vals.get(Provisioning.A_zimbraReverseProxyDomainNameAttribute);

                } catch (NginxLookupException e) {
                    ZimbraLog.nginxlookup.debug("domain not found for user " + unqualifiedName + ".  error: " + e.getMessage());
                }

                if (domainName != null)
                    NginxLookupExtension.sDomainNameByVirtualIpCache.put(new DomainInfo(serverIp, domainName));
            } else
                domainName = domainInfo.getDomainName();

            return domainName;
        }

        private DomainExternalRouteInfo getDomainExternalRouteInfoByDomainName(ILdapContext zlc, Config config,
                String domainName, String unqualifiedName) {
            DomainExternalRouteInfo domainExternalRouteInfo = NginxLookupExtension.sDomainExternalRouteByDomainNameCache.get(domainName);

            if (domainExternalRouteInfo == null) {
                try {
                    ZLdapFilter filter = ZLdapFilterFactory.getInstance().domainByName(domainName);
                    Map<String, Object> domainAttrs = ldapLookup.searchDir(zlc,
                            getDomainSC(config),
                            config,
                            filter,
                            Provisioning.A_zimbraReverseProxyDomainNameSearchBase);
                    String extRouteIncludeOrigAuthname = (String) domainAttrs.get(Provisioning.A_zimbraReverseProxyExternalRouteIncludeOriginalAuthusername);
                    if (extRouteIncludeOrigAuthname == null) {
                        extRouteIncludeOrigAuthname = config.getAttr(Provisioning.A_zimbraReverseProxyExternalRouteIncludeOriginalAuthusername, null);
                    }
                    domainExternalRouteInfo = new DomainExternalRouteInfo(domainName,
                            (String)domainAttrs.get(Provisioning.A_zimbraReverseProxyUseExternalRoute),
                            (String)domainAttrs.get(Provisioning.A_zimbraReverseProxyUseExternalRouteIfAccountNotExist),
                            extRouteIncludeOrigAuthname,
                            (String)domainAttrs.get(Provisioning.A_zimbraExternalPop3Port),
                            (String)domainAttrs.get(Provisioning.A_zimbraExternalPop3SSLPort),
                            (String)domainAttrs.get(Provisioning.A_zimbraExternalImapPort),
                            (String)domainAttrs.get(Provisioning.A_zimbraExternalImapSSLPort),
                            (String)domainAttrs.get(Provisioning.A_zimbraExternalPop3Hostname),
                            (String)domainAttrs.get(Provisioning.A_zimbraExternalPop3SSLHostname),
                            (String)domainAttrs.get(Provisioning.A_zimbraExternalImapHostname),
                            (String)domainAttrs.get(Provisioning.A_zimbraExternalImapSSLHostname));

                    NginxLookupExtension.sDomainExternalRouteByDomainNameCache.put(domainExternalRouteInfo);

                } catch (NginxLookupException e) {
                    ZimbraLog.nginxlookup.debug("domain not found for user while search doamin for external route:" +
                            "domain name =" + domainName + ", user name=" + unqualifiedName, e);
                }
            }

            return domainExternalRouteInfo;
        }

        private String getPort(Map<String, String> vals, String lookupAttr, Config config) {
            String port = vals.get(lookupAttr);
            if (port == null) {
                ZimbraLog.nginxlookup.debug("using port from globalConfig");
                String bindPortAttr = config.getAttr(lookupAttr);
                if (bindPortAttr == null)
                    ZimbraLog.nginxlookup.warn("missing config attr: "+lookupAttr);
                else {
                    port = config.getAttr(bindPortAttr);
                    if (port == null)
                        ZimbraLog.nginxlookup.warn("missing config attr: "+bindPortAttr);
                }
            }
            return port;
        }

        private String getPortByMailhostAndProto(ILdapContext zlc, Config config, NginxLookupRequest req, String mailhost)
        throws NginxLookupException {
            String port = null;

            ServerInfo serverInfo = NginxLookupExtension.sServerCache.get(mailhost);
            if (serverInfo == null) {
                // get all the ports and cache them
                Map<String, Boolean> attrs = new HashMap<String, Boolean>();
                attrs.put(Provisioning.A_zimbraReverseProxyHttpPortAttribute, false);
                attrs.put(Provisioning.A_zimbraReverseProxyHttpSSLPortAttribute, false);
                attrs.put(Provisioning.A_zimbraReverseProxyAdminPortAttribute, false);
                attrs.put(Provisioning.A_zimbraReverseProxyPop3PortAttribute, false);
                attrs.put(Provisioning.A_zimbraReverseProxyPop3SSLPortAttribute, false);
                attrs.put(Provisioning.A_zimbraReverseProxyImapPortAttribute, false);
                attrs.put(Provisioning.A_zimbraReverseProxyImapSSLPortAttribute, false);

                SearchDirResult sdr = ldapLookup.searchDirectory(
                        zlc,
                        getServerSC(config),
                        config,
                        FilterId.NGINX_GET_PORT_BY_MAILHOST,
                        Provisioning.A_zimbraReverseProxyPortQuery,
                        Provisioning.A_zimbraReverseProxyPortSearchBase,
                        "MAILHOST",
                        mailhost,
                        attrs,
                        null);

                Map<String, String> vals = sdr.configuredAttrs;
                serverInfo = new ServerInfo(mailhost);
                serverInfo.setHttpPort(getPort(vals, Provisioning.A_zimbraReverseProxyHttpPortAttribute, config));
                serverInfo.setHttpSSLPort(getPort(vals, Provisioning.A_zimbraReverseProxyHttpSSLPortAttribute, config));
                serverInfo.setHttpAdminPort(getPort(vals, Provisioning.A_zimbraReverseProxyAdminPortAttribute, config));
                serverInfo.setPop3Port(getPort(vals, Provisioning.A_zimbraReverseProxyPop3PortAttribute, config));
                serverInfo.setPop3SSLPort(getPort(vals, Provisioning.A_zimbraReverseProxyPop3SSLPortAttribute, config));
                serverInfo.setImapPort(getPort(vals, Provisioning.A_zimbraReverseProxyImapPortAttribute, config));
                serverInfo.setImapSSLPort(getPort(vals, Provisioning.A_zimbraReverseProxyImapSSLPortAttribute, config));

                NginxLookupExtension.sServerCache.put(serverInfo);
            }

            port = serverInfo.getPortForProto(req.proto, req.isZimbraAdmin);
            if (port == null)
                throw new NginxLookupException("missing port for protocol " + req.proto + " on server " + mailhost);

            return port;
        }

        private String qualifyUserName(ILdapContext zlc, Config config, NginxLookupRequest req, Provisioning prov, String unqualifiedName) {
            String domainName = null;

            if (HTTP.equalsIgnoreCase(req.proto)) {
                /* For HTTP, we need to qualify user based on virtual-host header */
                if (req.serverHost != null) {
                    ZimbraLog.nginxlookup.info("looking up domain by virtualhost name");
                    Domain d = null;
                    try {
                        d = prov.get(Key.DomainBy.virtualHostname, req.serverHost);
                    } catch (ServiceException e) {
                    }
                    if (d != null) {
                        domainName = d.getName();
                        ZimbraLog.nginxlookup.info("found domain:" + domainName + " for virtualhost:" + req.serverHost);
                    }
                }
            } else {
                /* For mail, we need to qualify user based on server-ip header */
                if (req.serverIp != null) {
                    domainName = getDomainNameByServerIp(zlc,config, req.serverIp, unqualifiedName);
                }
            }

            if (domainName == null) {
                domainName = config.getAttr(Provisioning.A_zimbraDefaultDomainName);
                ZimbraLog.nginxlookup.debug("domain not found for user " + unqualifiedName + ", using default domain: " + (domainName==null?"null":domainName));
            }

            String qualifiedName = unqualifiedName;
            if (domainName != null) {
                qualifiedName = unqualifiedName + "@" + domainName;
                ZimbraLog.nginxlookup.debug(AUTH_USER + " " + unqualifiedName + " is replaced by " + qualifiedName + " for mailhost lookup");
            } else {
                ZimbraLog.nginxlookup.warn("domain not found for user " + unqualifiedName);
            }

            return qualifiedName;
        }

        /** Qualifies the user-name, if necessary, by suffixing "@domain"
            The domain to be suffixed is the domain object whose zimbraVirtualIPAddress matches the
            IP address specified by req.serverIP (X-Proxy-IP request header)
            @return Fully qualified user name (or user-id), else the original user name
         */
        private String getQualifiedUsername(ILdapContext zlc, Config config, NginxLookupRequest req)
        throws ServiceException, NginxLookupException {
            String aUser, cUser, qUser;

            aUser = req.user;               /* AUTHZ (whose route is being discovered) */
            cUser = req.cuser;              /* AUTHC (if GSSAPI) */
            qUser = aUser;                  /* Qualified AUTHZ (defaults to AUTHZ) */

            Account gssapiAuthC = null;

            if (req.authMethod.equalsIgnoreCase(AUTHMETH_ZIMBRAID)) {
                /* For auth-token based routing, aUser contains the zimbraId of the user
                   No qualification is performed in this case, because the ldap query
                   can handle route lookup by ID also
                 */
                return qUser;
            } else if (req.authMethod.equalsIgnoreCase(AUTHMETH_GSSAPI)) {
                /* For GSSAPI, cUser specifies the authenticating kerberos principal
                   When no separate authorization ID was specified, then in this case,
                   aUser is equal to cUser, and therefore, by transition, aUser is also
                   interpreted as a kerberos principal

                   If a separate authorization ID has been specified, then in this case,
                   the authorization ID is treated in its own right as a fully qualified
                   or a partially qualified user name, and must be qualified according to
                   the regular qualification logic (See bug 24792)

                 */

                boolean authzIsPrincipal;

                authzIsPrincipal = aUser.equalsIgnoreCase(cUser);

                gssapiAuthC = prov.get(AccountBy.krb5Principal,cUser);
                if (gssapiAuthC == null) {
                    throw new NginxLookupException("No account was found which has kerberos principal " + cUser);
                }

                /* overwrite request::cuser (authenticating identity for gssapi) */
                req.cuser = gssapiAuthC.getAttr(Provisioning.A_zimbraMailDeliveryAddress);

                if (authzIsPrincipal) {
                    qUser = gssapiAuthC.getAttr(Provisioning.A_zimbraMailDeliveryAddress);
                }
            } else if (req.authMethod.equalsIgnoreCase(AUTHMETH_CERTAUTH)) {
                Account certAuthAcct = ClientCertAuthenticator.getAccountByX509SubjectDN(req.user);
                if (certAuthAcct == null) {
                    throw new NginxLookupException("account not found: " + req.user);
                }
                req.pass = genAuthToken(certAuthAcct, config, req);
                return certAuthAcct.getName();
            }

            /* At this point, qUser is may not be fully qualified, and so the domain must be looked up
               depending upon which protocol is being used

               For HTTP, the host header must be used in order to lookup the domain by zimbraVirtualHostname
               For MAIL, the proxy ip must be used in order to lookup the domain by zimbraVirtualIPAddress
            */
            if (qUser.indexOf('@') == -1)
                qUser = qualifyUserName(zlc, config, req, prov, aUser);

            if (req.authMethod.equalsIgnoreCase(AUTHMETH_GSSAPI)) {
                /* Now, qUser is as qualified as it is ever going to get.
                   Perform access checks to see whether req.cuser is allowed to act as qUser.
                 */
                Account gssapiAuthZ = prov.get(AccountBy.name, qUser);
                if (gssapiAuthZ == null)
                    throw new NginxLookupException("account not found: " + qUser);

                if (!gssapiAuthC.getId().equals(gssapiAuthZ.getId()) &&
                    !AccessManager.getInstance().canAccessAccount(gssapiAuthC, gssapiAuthZ, true))
                    throw new NginxLookupException("authorization failed for " + gssapiAuthZ.getName() + " (authenticated user " + gssapiAuthC.getName() + " has insufficient rights)");

                /*
                 * finally, all is well, send back an auth-token as a password
                 * req.pass = "0_7e6c9784e1e3d27c311282220c2bc61e4db1bd48_69643d33363a66653664656239372d303162362d346463362d623662312d3265393634333238383931623b6578703d31333a313231353335393937333231333b747970653d363a7a696d6272613b";
                 */
                req.pass = genAuthToken(gssapiAuthC, config, req);
            }
            return qUser;
        }

        private boolean isMailProtocol(String proto) {
            return (NginxLookupHandler.POP3.equalsIgnoreCase(proto) ||
                    NginxLookupHandler.POP3_SSL.equalsIgnoreCase(proto) ||
                    NginxLookupHandler.IMAP.equalsIgnoreCase(proto) ||
                    NginxLookupHandler.IMAP_SSL.equalsIgnoreCase(proto));
        }

        private String getExternalHostnameOnAccount(String proto, Map<String, String> vals) {
            if (NginxLookupHandler.POP3.equalsIgnoreCase(proto))
                return vals.get(Provisioning.A_zimbraExternalPop3Hostname);
            else if (NginxLookupHandler.POP3_SSL.equalsIgnoreCase(proto))
                return vals.get(Provisioning.A_zimbraExternalPop3SSLHostname);
            else if (NginxLookupHandler.IMAP.equalsIgnoreCase(proto))
                return vals.get(Provisioning.A_zimbraExternalImapHostname);
            else if (NginxLookupHandler.IMAP_SSL.equalsIgnoreCase(proto))
                return vals.get(Provisioning.A_zimbraExternalImapSSLHostname);
            return null;
        }

        private String getExternalPortOnAccount(String proto, Map<String, String> vals) {
            if (NginxLookupHandler.POP3.equalsIgnoreCase(proto))
                return vals.get(Provisioning.A_zimbraExternalPop3Port);
            else if (NginxLookupHandler.POP3_SSL.equalsIgnoreCase(proto))
                return vals.get(Provisioning.A_zimbraExternalPop3SSLPort);
            else if (NginxLookupHandler.IMAP.equalsIgnoreCase(proto))
                return vals.get(Provisioning.A_zimbraExternalImapPort);
            else if (NginxLookupHandler.IMAP_SSL.equalsIgnoreCase(proto))
                return vals.get(Provisioning.A_zimbraExternalImapSSLPort);
            return null;
        }

        private DomainExternalRouteInfo getDomainExternalRouteInfo(ILdapContext zlc, Config config, String addr) {
            DomainExternalRouteInfo domain = null;
            String[] parts = addr.split("@");
            if (parts.length == 2) {
                String domainName = parts[1];
                domain = getDomainExternalRouteInfoByDomainName(zlc, config, domainName, addr);

            }
            if (domain == null)
                ZimbraLog.nginxlookup.debug("cannot find domain for external route info, user=" + addr);
            return domain;
        }

        void search(NginxLookupRequest req, NginxLookupResponse res) throws NginxLookupException {
            ILdapContext zlc = null;
            try {
                zlc = ldapLookup.getLdapContext();

                Config config = prov.getConfig();
                String authUser = getQualifiedUsername(zlc, config, req);

                // verify the account is an admin or delegated admin when request ask for admin
                // route, certauth, ...
                if(req.isZimbraAdmin) {
                    verifyAccountAdmin(authUser, req.authMethod);
                }

                // Check if the client IP matches one of the IPs in zimbraReverseProxyDomainAllowedIPs
                Account acct = null;
                if (req.authMethod.compareToIgnoreCase(AUTHMETH_ZIMBRAID) == 0) {
                    acct = prov.get(AccountBy.id, authUser);
                } else {
                    acct = prov.get(AccountBy.name, authUser);
                }
                if (acct != null) {
                    Domain userdomain = prov.getDomain(acct);
                    if (userdomain == null)
                        throw new EntryNotFoundException("domain not found for user:" + authUser);
                    String[] DomainAllowedIPs = userdomain
                         .getMultiAttr(Provisioning.A_zimbraDomainAllowedIPs);
                    ZimbraLog.nginxlookup.debug("Domain name is " + userdomain.getName() + " & DomainAllowedIPs list is " + Arrays.asList(DomainAllowedIPs));

                    int i = 0;
                    for (; i < DomainAllowedIPs.length; i++) {
                        // Check if each entry in DomainAllowedIPs is an IP subnet (in CIDR notation eg.x.x.x.y/24) or just a single IP (eg. x.x.x.y)
                        String ipaddr = DomainAllowedIPs[i];
                        if (ipaddr.indexOf("/") == -1) {
                            if (ipaddr.equals(req.clientIp))
                                break;
                        } else {
                            SubnetUtils utils = new SubnetUtils(ipaddr);
                            SubnetInfo info = utils.getInfo();
                            if (info.isInRange(req.clientIp))
                                break;
                        }
                    }
                    if (DomainAllowedIPs.length > 0 && i == DomainAllowedIPs.length)
                        throw new NginxLookupException(CLIENT_IP + " " + req.clientIp + " " + ACCESS_DENIED_ERRMSG);
                }

                if (req.authMethod.equalsIgnoreCase(AUTHMETH_CERTAUTH)) {
                	// for cert auth, no need to find the real route, just
                	// send back zm_auth_token or zm_admin_auth_token
                	sendResult(req, res, "127.0.0.1", "9999", authUser, false, false);
                	return;
                }

                // bug 37266, support proxy-side dns lookup
                boolean doDnsLookup = true;
                Server server = prov.getLocalServer();
                if (server == null) {
                    doDnsLookup = prov.getConfig().
                                    getBooleanAttr(Provisioning.A_zimbraReverseProxyDnsLookupInServerEnabled, true);
                } else {
                    doDnsLookup = server.getBooleanAttr(Provisioning.A_zimbraReverseProxyDnsLookupInServerEnabled, true);
                }

                Map<String, Boolean> attrs = new HashMap<String, Boolean>();
                attrs.put(Provisioning.A_zimbraReverseProxyMailHostAttribute, false);
                attrs.put(Provisioning.A_zimbraReverseProxyUserNameAttribute, false);

                Set<String> extraAttrs = new HashSet<String>();
                extraAttrs.add(Provisioning.A_zimbraReverseProxyUseExternalRoute);
                extraAttrs.add(Provisioning.A_zimbraExternalPop3Port);
                extraAttrs.add(Provisioning.A_zimbraExternalPop3SSLPort);
                extraAttrs.add(Provisioning.A_zimbraExternalImapPort);
                extraAttrs.add(Provisioning.A_zimbraExternalImapSSLPort);
                extraAttrs.add(Provisioning.A_zimbraExternalPop3Hostname);
                extraAttrs.add(Provisioning.A_zimbraExternalPop3SSLHostname);
                extraAttrs.add(Provisioning.A_zimbraExternalImapHostname);
                extraAttrs.add(Provisioning.A_zimbraExternalImapSSLHostname);

                SearchDirResult sdr = null;

                String authUserWithRealDomainName = authUser;
                try {
                    sdr = ldapLookup.searchDirectory(
                            zlc,
                            getUserSC(config),
                            config,
                            FilterId.NGINX_GET_MAILHOST,
                            Provisioning.A_zimbraReverseProxyMailHostQuery,
                            Provisioning.A_zimbraReverseProxyMailHostSearchBase,
                            "USER",
                            authUser,
                            attrs,
                            extraAttrs);
                } catch (EntryNotFoundException e) {
                    ZimbraLog.nginxlookup.debug("user " + authUser + " not found", e);
                }

                // not found.  Domain part of authUser could contain an alias domain name.
                // If so, try the search again with the domain part converted to the real domain name.
                if (sdr == null) {
                    //
                    // Note: do *not* replace the name to be returned to the client(nginx)
                    //       the name should not be rewritten when the input name is an
                    //       alias or a name with domain alias.
                    //
                    authUserWithRealDomainName = prov.getEmailAddrByDomainAlias(authUser);

                    if (authUserWithRealDomainName != null) {
                        ZimbraLog.nginxlookup.debug("retrying with resolved domain alias: " + authUserWithRealDomainName);
                        try {
                            sdr = ldapLookup.searchDirectory(
                                    zlc,
                                    getUserSC(config),
                                    config,
                                    FilterId.NGINX_GET_MAILHOST,
                                    Provisioning.A_zimbraReverseProxyMailHostQuery,
                                    Provisioning.A_zimbraReverseProxyMailHostSearchBase,
                                    "USER",
                                    authUserWithRealDomainName,
                                    attrs,
                                    extraAttrs);
                        } catch (EntryNotFoundException e) {
                            ZimbraLog.nginxlookup.debug("user " + authUserWithRealDomainName + " not found", e);
                        }
                    } else {
                        // no luck in alias domain lookup, set it back
                        authUserWithRealDomainName = authUser;
                    }
                }

                String mailhost = null;
                String port = null;

                // if still not found, see if we should use external route based on a domain setting
                if (sdr == null) {
                    DomainExternalRouteInfo domain = getDomainExternalRouteInfo(zlc, config, authUserWithRealDomainName);
                    if (domain == null || !domain.useExternalRouteIfAccountNotExist())
                        throw new EntryNotFoundException("user not found:" + authUserWithRealDomainName);

                    mailhost = domain.getHostname(req.proto);
                    port = domain.getPort(req.proto);

                    if (mailhost == null || port == null)
                        throw new EntryNotFoundException("user not found: " + authUserWithRealDomainName +
                            ". domain " + domain.getDomainName() + " has " +
                            Provisioning.A_zimbraReverseProxyUseExternalRouteIfAccountNotExist + " set to TRUE " +
                            "but missing external route info on domain");
                    if(doDnsLookup) {
                        mailhost = IPUtil.getIPByIPMode(prov, mailhost).getHostAddress();
                    }
                    sendResult(req, res, mailhost, port, authUser, false, false);
                    return;
                }

                Map<String, String> vals = sdr.configuredAttrs;
                String userName = vals.get(Provisioning.A_zimbraReverseProxyUserNameAttribute);
                if (userName != null)
                    authUser = authUserWithRealDomainName = userName;

                //
                // see if we should use external route
                //
                Map<String, String> extraAttrsVals = sdr.extraAttrs;
                DomainExternalRouteInfo domain = null;
                boolean domainNotFound = false;

                // external route is only applicable to mail protocols
                boolean useExternalRoute = isMailProtocol(req.proto);

                if (useExternalRoute) {
                    String useExtRouteOnAcct = extraAttrsVals.get(Provisioning.A_zimbraReverseProxyUseExternalRoute);
                    if (useExtRouteOnAcct == null) {
                        // check if it is set on domain
                        domain = getDomainExternalRouteInfo(zlc, config, authUserWithRealDomainName);
                        if (domain == null) {
                            // don't throw, just fallback to use internal route
                            ZimbraLog.nginxlookup.warn("cannot find domain for external route info, fallback to use internal route, user=" + authUserWithRealDomainName);
                            domainNotFound = true;
                            useExternalRoute = false;
                        } else
                            useExternalRoute = domain.useExternalRoute();
                    } else {
                        useExternalRoute = ProvisioningConstants.TRUE.equals(useExtRouteOnAcct);
                    }
                }
                boolean externalRouteIncludeOriginalAuthusername = false;
                if (useExternalRoute) {
                    ZimbraLog.nginxlookup.debug("fetching external route for user " + authUserWithRealDomainName);

                    // get whether you need to include domain name
                    if (domain == null && !domainNotFound) {
                        domain = getDomainExternalRouteInfo(zlc, config, authUserWithRealDomainName);
                    }
                    externalRouteIncludeOriginalAuthusername = domain == null ?
                        prov.getDefaultDomain().isReverseProxyExternalRouteIncludeOriginalAuthusername() :
                        domain.externalRouteIncludeOriginalAuthusername();

                    // get external host/port on account
                    mailhost = getExternalHostnameOnAccount(req.proto, extraAttrsVals);
                    port = getExternalPortOnAccount(req.proto, extraAttrsVals);

                    if (mailhost == null || port == null) {
                        // not set or not set completely on account, try domain

                        if (domain == null) {
                            ZimbraLog.nginxlookup.warn("cannot find domain for external route info, fallback to use internal route, user=" + authUserWithRealDomainName );
                        } else {
                            mailhost = domain.getHostname(req.proto);
                            port = domain.getPort(req.proto);
                        }
                    }

                    // external host/port not set or not set completely on account/domain, null both and
                    // we will fallback to the internal route
                    if (mailhost == null || port == null) {
                        ZimbraLog.nginxlookup.info("account " + authUserWithRealDomainName + " has " +
                                    Provisioning.A_zimbraReverseProxyUseExternalRoute + " set to TRUE " +
                                    " but missing external route info, fallback to use internal route");
                        mailhost = null;
                        port = null;
                    } else
                        ZimbraLog.nginxlookup.debug("External route for user=%s, host=%s, port=%s", authUserWithRealDomainName, mailhost, port);
                }

                // use internal route

                // When an account is already assigned a server in LDAP.
                if (mailhost == null && (acct == null || acct.getServer() != null)) {
                    mailhost = vals.get(Provisioning.A_zimbraReverseProxyMailHostAttribute);
                }

                // If an account is already assigned a server in LDAP, then nginx
                // would have ordinarily received a memcached cache hit. So we're here either because the
                // cache is warming up, or because nginx detected that the account's usual upstream is dead.
                // So in all cases we'll query the service locator to ensure the assigned mailstore is healthy right now.
                String serviceID = getServiceIDForProto(req.proto);
                boolean checkUpstreamHealth = DebugConfig.isNginxLookupServerReassignOnHealthCheckEnabled()
                        && mailhost != null
                        && (acct == null || !acct.isAccountExternal())
                        && (acct == null || acct.getClusterId() != null);
                if (checkUpstreamHealth) {
                    boolean healthy = true;
                    try {
                        healthy = serviceLocator.isHealthy(serviceID, mailhost);
                    } catch (IOException e) {
                        ZimbraLog.nginxlookup.warn("Could not reach service locator to determine whether mailstore %s is healthy for user %s via service id %s for protocol %s; skipping any potential mailstore reassignment", mailhost, authUserWithRealDomainName, serviceID, req.proto, e);
                    } catch (ServiceException e) {
                        healthy = false;
                    }
                    if (!healthy) {
                        ZimbraLog.nginxlookup.warn("mailstore %s is not healthy for user %s; reassigning", mailhost, authUserWithRealDomainName);
                        mailhost = null;
                    }
                }

                // When an account is not assigned a server in LDAP, use the service locator to pick one
                if (acct != null && mailhost == null) {
                    ZimbraLog.nginxlookup.debug("No mailhost found for user %s; using service locator to select a new upstream", req.user);
                    ServiceLocator.Entry serviceInfo = null;
                    try {
                        Selector<ServiceLocator.Entry> selector = Zimbra.getAppContext().getBean(Selector.class);
                        serviceInfo = serviceLocator.findOne(serviceID, selector, null, true);
                    } catch (IOException e) {
                        ZimbraLog.nginxlookup.warn("Could not reach service locator to select a new mailstore for user %s and service id %s for protocol %s; skipping mailstore assignment", authUserWithRealDomainName, serviceID, req.proto, e);
                    }
                    if (serviceInfo != null) {
                        mailhost = serviceInfo.hostName;
                        port = Integer.toString(serviceInfo.servicePort);

                        // permanently assign the account to the newly selected server
                        acct.setMailHost(mailhost);
                        ZimbraLog.nginxlookup.info("User %s is now assigned to mailhost %s", req.user, mailhost);
                    }
                }

                if (mailhost != null) {
                    if (port == null)
                        port = getPortByMailhostAndProto(zlc, config, req, mailhost);
                    if (doDnsLookup) {
                        mailhost = IPUtil.getIPByIPMode(prov, mailhost).getHostAddress();
                    }
                }

                sendResult(req, res, mailhost, port, authUser, useExternalRoute, externalRouteIncludeOriginalAuthusername);
            } catch (NginxLookupException e) {
                throw e;
            } catch (ServiceException e) {
                throw new NginxLookupException(e);
            } catch (UnknownHostException e) {
                throw new NginxLookupException(e);
            } catch (Exception e) {
                throw new NginxLookupException(e);
            } finally {
                ldapLookup.closeLdapContext(zlc);
            }
        }

        /**
         * Send the routing information HTTP response back to the NGINX IMAP proxy
         * @param req    The HTTP request object
         * @param mailhost    The requested mail server name
         * @param port        The requested mail server port
         * @param authUser    If not null, then this value is sent back to override the login
         *                     user name, (usually) with a domain suffix added
         * @param useExternalRoute If true, then externalRouteIncludeOriginalAuthusername is checked
         *                          to return original req username unmodified
         * @param externalRouteIncludeOriginalAuthusername - include original username as requested
         */
        private void sendResult(NginxLookupRequest req, NginxLookupResponse res, String addr, String port, String authUser, boolean useExternalRoute, boolean externalRouteIncludeOriginalAuthusername) throws UnknownHostException {
            ZimbraLog.nginxlookup.debug("mailhost=" + addr);
            ZimbraLog.nginxlookup.debug("port=" + port);
            ZimbraLog.nginxlookup.debug("clientIp=" + req.clientIp);

            HttpServletResponse resp = res.httpResp;
            resp.setStatus(HttpServletResponse.SC_OK);
            resp.addHeader(AUTH_STATUS, "OK");
            resp.addHeader(AUTH_SERVER, addr);
            resp.addHeader(AUTH_PORT, port);
            try {
                if (StringUtil.equal(prov.getDomainByEmailAddr(authUser).getName(),
                        prov.getConfig().getDefaultDomainName())) {
                    resp.addHeader(AUTH_CACHE_ALIAS, "TRUE");
                } else {
                    resp.addHeader(AUTH_CACHE_ALIAS, "FALSE");
                }
            } catch (ServiceException e) {
                // turn off alias cache if authUser is empty or if any error
                resp.addHeader(AUTH_CACHE_ALIAS, "FALSE");
            }

            if (useExternalRoute && externalRouteIncludeOriginalAuthusername) {
                authUser = req.user;
            }

            if (authUser != null) {
                ZimbraLog.nginxlookup.debug("rewrite " + AUTH_USER + " to: " + authUser);
                /* encode authUser, %-->%25 ' '-->%20 */
                authUser = authUser.replace(" ", "%20");
                authUser = authUser.replace("%", "%25");
                resp.addHeader(AUTH_USER, authUser);
            }

            if (req.authMethod.equalsIgnoreCase(AUTHMETH_GSSAPI)) {
                // For GSSAPI, we also need to send back the overriden authenticating ID and the auth-token as password
                resp.addHeader(AUTH_ID, req.cuser);
                resp.addHeader(AUTH_PASS, req.pass);
            } else if (req.authMethod.equalsIgnoreCase(AUTHMETH_CERTAUTH)) {
                // For CERTAUTH, we also need to send back the auth-token as password
                resp.addHeader(AUTH_PASS, req.pass);
            }
        }

        /**
         * Indicate an error to the calling (NGINX) proxy
         * @param resp  The HTTP response object
         * @param msg   The error message (a generic error message is sent back to the caller, the original message is logged)
         */
        private void sendError(HttpServletResponse resp, String msg) {

            ZimbraLog.nginxlookup.info(msg);
            resp.setStatus(HttpServletResponse.SC_OK);
            resp.addHeader(AUTH_STATUS, msg);

            String waitInterval = null;
            try {
                Config config = prov.getConfig();
                long wi = config.getTimeIntervalSecs(Provisioning.A_zimbraReverseProxyAuthWaitInterval, DEFAULT_WAIT_INTERVAL);
                waitInterval = "" + wi;
            } catch (ServiceException e) {
                ZimbraLog.nginxlookup.warn("cannot get config");
                waitInterval = "" + DEFAULT_WAIT_INTERVAL;
            }
            resp.addHeader(AUTH_WAIT, waitInterval);
        }
    }