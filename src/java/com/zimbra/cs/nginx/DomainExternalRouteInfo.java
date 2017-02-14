/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2008, 2009, 2010, 2011, 2013, 2014, 2016 Synacor, Inc.
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
package com.zimbra.cs.nginx;

import com.zimbra.cs.ldap.LdapConstants;

public class DomainExternalRouteInfo extends LookupEntry {
    
    private boolean mUseExternalRoute;
    private boolean mUseExternalRouteIfAccountNotExist;
    private boolean mExternalRouteIncludeOriginalAuthusername;
    
    private String mPop3Port;
    private String mPop3SSLPort;
    private String mImapPort;
    private String mImapSSLPort;
    private String mPop3Hostname;
    private String mPop3SSLHostname;
    private String mImapHostname;
    private String mImapSSLHostname;
    
    DomainExternalRouteInfo(String domainName,
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
        super(domainName);
        
        mUseExternalRoute = LdapConstants.LDAP_TRUE.equals(useExternalRoute);
        mUseExternalRouteIfAccountNotExist = LdapConstants.LDAP_TRUE.equals(useExternalRouteIfAccountNotExist);
        mExternalRouteIncludeOriginalAuthusername = LdapConstants.LDAP_TRUE.equals(externalRouteIncludeOriginalAuthusername);

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
        if (NginxLookupExtension.NginxLookupHandler.POP3.equalsIgnoreCase(proto))
            return mPop3Hostname;
        else if (NginxLookupExtension.NginxLookupHandler.POP3_SSL.equalsIgnoreCase(proto))
            return mPop3SSLHostname;
        else if (NginxLookupExtension.NginxLookupHandler.IMAP.equalsIgnoreCase(proto))
            return mImapHostname;
        else if (NginxLookupExtension.NginxLookupHandler.IMAP_SSL.equalsIgnoreCase(proto))
            return mImapSSLHostname;
        else
            return null;
    }
    
    String getPort(String proto) {
        if (NginxLookupExtension.NginxLookupHandler.POP3.equalsIgnoreCase(proto))
            return mPop3Port;
        else if (NginxLookupExtension.NginxLookupHandler.POP3_SSL.equalsIgnoreCase(proto))
            return mPop3SSLPort;
        else if (NginxLookupExtension.NginxLookupHandler.IMAP.equalsIgnoreCase(proto))
            return mImapPort;
        else if (NginxLookupExtension.NginxLookupHandler.IMAP_SSL.equalsIgnoreCase(proto))
            return mImapSSLPort;
        else
            return null;
    }

}

