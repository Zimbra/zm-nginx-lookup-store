package com.zimbra.cs.account;

public class UnitTestServer extends Server {
    private String[] reverseProxyUpstreamImapServers = null;
    private String hostname = null;

    public UnitTestServer (String[] reverseProxyUpstreamImapServers, String hostname,  Provisioning prov){
        super(hostname, null, null, null, prov);
        this.reverseProxyUpstreamImapServers = reverseProxyUpstreamImapServers;
        this.hostname = hostname;
    }

    @Override
    public String[] getReverseProxyUpstreamImapServers() {
        return reverseProxyUpstreamImapServers;
    }

    @Override
    public String getServiceHostname() {
        return this.hostname;
    }

    public String toString()
    {
        return "UnitTestServer(" + this.hostname + ")";
    }

    @Override
    public String getImapBindPortAsString() {
        return "imap-internal";
    }

    @Override
    public String getImapSSLBindPortAsString() {
        return "imaps-internal";
    }

    @Override
    public String getRemoteImapBindPortAsString() {
        return "imap-remote";
    }

    @Override
    public String getRemoteImapSSLBindPortAsString() {
        return "imaps-remote";
    }
}
