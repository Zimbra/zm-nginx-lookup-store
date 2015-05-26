/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2008, 2009, 2010, 2011, 2013, 2014 Zimbra, Inc.
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

import com.zimbra.cs.ldap.LdapConstants;

public class DomainExternalRouteInfo extends LookupEntry {

    private final boolean mUseExternalRoute;
    private final boolean mUseExternalRouteIfAccountNotExist;
    private final boolean mExternalRouteIncludeOriginalAuthusername;

    private final String mPop3Port;
    private final String mPop3SSLPort;
    private final String mImapPort;
    private final String mImapSSLPort;
    private final String mPop3Hostname;
    private final String mPop3SSLHostname;
    private final String mImapHostname;
    private final String mImapSSLHostname;

    DomainExternalRouteInfo(String domainName, String domainDN, String entryCSN, String configEntryCSN,
                            String useExternalRoute,
                            String useExternalRouteIfAccountNotExist,
                            String externalRouteIncludeOriginalAuthusername,
                            String pop3Port,
                            String pop3SSLPort,
                            String imapPort,
                            String imapSSLPort,
                            String pop3Hostname,
                            String pop3SSLHostname,
                            String imapHostname,
                            String imapSSLHostname) {
        super(domainName, domainDN, entryCSN, configEntryCSN);

        mUseExternalRoute = LdapConstants.LDAP_TRUE.equals(useExternalRoute);
        mUseExternalRouteIfAccountNotExist = LdapConstants.LDAP_TRUE.equals(useExternalRouteIfAccountNotExist);
        mExternalRouteIncludeOriginalAuthusername =
                LdapConstants.LDAP_TRUE.equals(externalRouteIncludeOriginalAuthusername);

        mPop3Port        = pop3Port;
        mPop3SSLPort     = pop3SSLPort;
        mImapPort        = imapPort;
        mImapSSLPort     = imapSSLPort;
        mPop3Hostname    = pop3Hostname;
        mPop3SSLHostname = pop3SSLHostname;
        mImapHostname    = imapHostname;
        mImapSSLHostname = imapSSLHostname;
    }

    String getDomainName() {
        return getKey();
    }

    boolean useExternalRoute() {
        return mUseExternalRoute;
    }

    boolean useExternalRouteIfAccountNotExist() {
        return mUseExternalRouteIfAccountNotExist;
    }

    boolean externalRouteIncludeOriginalAuthusername() {
        return mExternalRouteIncludeOriginalAuthusername;
    }

    String getHostname(String proto) {
        if (NginxLookupHandler.POP3.equalsIgnoreCase(proto))
            return mPop3Hostname;
        else if (NginxLookupHandler.POP3_SSL.equalsIgnoreCase(proto))
            return mPop3SSLHostname;
        else if (NginxLookupHandler.IMAP.equalsIgnoreCase(proto))
            return mImapHostname;
        else if (NginxLookupHandler.IMAP_SSL.equalsIgnoreCase(proto))
            return mImapSSLHostname;
        else
            return null;
    }

    String getPort(String proto) {
        if (NginxLookupHandler.POP3.equalsIgnoreCase(proto))
            return mPop3Port;
        else if (NginxLookupHandler.POP3_SSL.equalsIgnoreCase(proto))
            return mPop3SSLPort;
        else if (NginxLookupHandler.IMAP.equalsIgnoreCase(proto))
            return mImapPort;
        else if (NginxLookupHandler.IMAP_SSL.equalsIgnoreCase(proto))
            return mImapSSLPort;
        else
            return null;
    }

}

