/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Zimbra, Inc.
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

public class ServerInfo extends LookupEntry {

    private String mHttpPort;
    private String mHttpSSLPort;
    private String mHttpAdminPort;
    private String mPop3Port;
    private String mPop3SSLPort;
    private String mImapPort;
    private String mImapSSLPort;

    ServerInfo(String serverName, String dn, String entryCSN, String configEntryCSN) {
        super(serverName, dn, entryCSN, configEntryCSN);
    }

    void setHttpPort(String port) {
        mHttpPort = port;
    }

    void setHttpSSLPort(String port) {
        mHttpSSLPort = port;
    }

    void setHttpAdminPort(String port) {
        mHttpAdminPort = port;
    }

    void setPop3Port(String port) {
        mPop3Port = port;
    }

    void setPop3SSLPort(String port) {
        mPop3SSLPort = port;
    }

    void setImapPort(String port) {
        mImapPort = port;
    }

    void setImapSSLPort(String port) {
        mImapSSLPort = port;
    }

    String getPortForProto(String proto, boolean isZimbraAdmin) {
        if (NginxLookupHandler.POP3.equalsIgnoreCase(proto))
            return mPop3Port;
        else if (NginxLookupHandler.POP3_SSL.equalsIgnoreCase(proto))
            return mPop3SSLPort;
        else if (NginxLookupHandler.IMAP.equalsIgnoreCase(proto))
            return mImapPort;
        else if (NginxLookupHandler.IMAP_SSL.equalsIgnoreCase(proto))
            return mImapSSLPort;
        else if (NginxLookupHandler.HTTP.equalsIgnoreCase(proto)) {
            return mHttpPort;
        } else if (NginxLookupHandler.HTTP_SSL.equalsIgnoreCase(proto)) {
            if (isZimbraAdmin) {
                return mHttpAdminPort;
            } else {
                return mHttpSSLPort;
            }
        }

        return null;
    }
}

