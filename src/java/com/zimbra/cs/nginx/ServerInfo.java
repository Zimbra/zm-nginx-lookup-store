/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2016 Synacor, Inc.
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

public class ServerInfo extends LookupEntry {
    private static final String ZX_HTTP_PORT = "8742";
    private static final String ZX_HTTPS_PORT = "8743";

    private String mHttpPort;
    private String mHttpSSLPort;
    private String mHttpAdminPort;
    private String mHttpPop3Port;
    private String mHttpPop3SSLPort;
    private String mHttpImapPort;
    private String mHttpImapSSLPort;
    
    ServerInfo(String serverName) {
        super(serverName);
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
        mHttpPop3Port = port;
    }
    
    void setPop3SSLPort(String port) {
        mHttpPop3SSLPort = port;
    }
    
    void setImapPort(String port) {
        mHttpImapPort = port;
    }
    
    void setImapSSLPort(String port) {
        mHttpImapSSLPort = port;
    }
    
    String getPortForProto(String proto, NginxLookupExtension.NginxLookupRequestType type) {
        if (NginxLookupExtension.NginxLookupHandler.POP3.equalsIgnoreCase(proto))
            return mHttpPop3Port;
        else if (NginxLookupExtension.NginxLookupHandler.POP3_SSL.equalsIgnoreCase(proto))
            return mHttpPop3SSLPort;
        else if (NginxLookupExtension.NginxLookupHandler.IMAP.equalsIgnoreCase(proto))
            return mHttpImapPort;
        else if (NginxLookupExtension.NginxLookupHandler.IMAP_SSL.equalsIgnoreCase(proto))
            return mHttpImapSSLPort;
        else if (NginxLookupExtension.NginxLookupHandler.HTTP.equalsIgnoreCase(proto)) {
            if (type == NginxLookupExtension.NginxLookupRequestType.zx) {
                return ZX_HTTP_PORT;
            } else {
                return mHttpPort;
            }
        } else if (NginxLookupExtension.NginxLookupHandler.HTTP_SSL.equalsIgnoreCase(proto)) {
            if (type == NginxLookupExtension.NginxLookupRequestType.zx) {
                return ZX_HTTPS_PORT;
            } else if (type == NginxLookupExtension.NginxLookupRequestType.admin) {
                return mHttpAdminPort;
            } else {
                return mHttpSSLPort;
            }
        }
        
        return null;
    }
}

