package com.zimbra.cs.account;

public class UnitTestAccount extends Account {
    private Server server = null;
    private String id = null;

    public UnitTestAccount(String name, String id, Provisioning prov, Server server) {
        super(name, id, null, null, prov);
        this.id = id;
        this.server = server;
    }

    @Override
    public Server getServer() {
        return server;
    }

    @Override
    public String getId() {
        return id;
    }
}
