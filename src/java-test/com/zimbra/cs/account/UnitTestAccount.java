package com.zimbra.cs.account;

public class UnitTestAccount extends Account {
    private Server server = null;

    public UnitTestAccount(String name, Provisioning prov, Server server) {
        super(name, null, null, null, prov);
        this.server = server;
    }

    @Override
    public Server getServer() {
        return server;
    }
}
