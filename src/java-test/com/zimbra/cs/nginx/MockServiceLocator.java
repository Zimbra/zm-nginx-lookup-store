/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2014 Zimbra, Inc.
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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.google.common.base.Objects;
import com.zimbra.common.consul.CatalogRegistration;
import com.zimbra.common.service.ServiceException;
import com.zimbra.common.servicelocator.Selector;
import com.zimbra.common.servicelocator.ServiceLocator;

public class MockServiceLocator implements ServiceLocator {
    List<Record> services = new ArrayList<>();

    @Override
    public void deregister(String serviceID) throws IOException, ServiceException {

    }

    @Override
    public void deregisterSilent(String serviceID) {
        try {
            deregister(serviceID);
        } catch (IOException | ServiceException e) {}
    }

    @Override
    public List<ServiceLocator.Entry> find(String serviceName, boolean healthyOnly) throws IOException, ServiceException {
        List<ServiceLocator.Entry> result = new ArrayList<>();
        for (Record record: services) {
            if (Objects.equal(serviceName, record.serviceID)) {
                if (healthyOnly == false || (healthyOnly && record.healthy)) {
                    result.add(new ServiceLocator.Entry(record.hostName, record.hostAddress, record.servicePort));
                }
            }
        }
        return result;
    }

    @Override
    public Entry findOne(String serviceName, Selector selector, boolean healthyOnly) throws IOException, ServiceException {
        List<Entry> list = find(serviceName, true);
        if (list.isEmpty() && !healthyOnly) {
            list = find(serviceName, false);
        }
        if (list.isEmpty()) {
            throw ServiceException.NOT_FOUND("No healthy instances of " + serviceName);
        }
        return selector.selectOne(list);
    }

    @Override
    public boolean isHealthy(String serviceID, String hostName) throws IOException, ServiceException {
        for (Record record: services) {
            if (!Objects.equal(serviceID, record.serviceID)) {
                continue;
            }
            if (!hostName.equalsIgnoreCase(record.hostName)) {
                continue;
            }
            return record.healthy;
        }
        throw ServiceException.NOT_FOUND("No such service");
    }

    @Override
    public void ping() throws IOException {}

    @Override
    public void register(CatalogRegistration.Service service) throws IOException, ServiceException {}

    @Override
    public void registerSilent(CatalogRegistration.Service service) {}

    public void add(String serviceID, String hostName, String hostAddress, int port) {
        services.add(new Record(serviceID, hostName, hostAddress, port));
    }

    /** Remove a service entry, identified by a serviceID, (hostName or hostAddress), and a servicePort */
    public void remove(String serviceID, String hostName, String hostAddress, int servicePort) {
        Record compareTo = new Record(serviceID, hostName, hostAddress, servicePort);
        for (Iterator<Record> iter = services.iterator(); iter.hasNext(); ) {
            Record record = iter.next();
            if (!record.equals(compareTo)) {
                continue;
            }
            iter.remove();
            break;
        }
    }

    public void setHealthy(String serviceID, String hostName, boolean healthy) throws IOException, ServiceException {
        for (Record record: services) {
            if (!Objects.equal(serviceID, record.serviceID)) {
                continue;
            }
            if (!hostName.equalsIgnoreCase(record.hostName)) {
                continue;
            }
            record.healthy = healthy;
        }
    }

    class Record {
        protected String serviceID, hostName, hostAddress;
        protected int servicePort;
        protected boolean healthy;

        public Record(String serviceID, String hostName, String hostAddress, int servicePort) {
            this.serviceID = serviceID;
            this.hostName = hostName;
            this.hostAddress = hostAddress;
            this.servicePort = servicePort;
            healthy = true;
        }

        public boolean equals(Object object) {
            if (!(object instanceof Record)) {
                throw new ClassCastException();
            }
            Record record = (Record)object;
            if (!Objects.equal(serviceID, record.serviceID)) {
                return false;
            }
            if (servicePort != record.servicePort) {
                return false;
            }
            if (!Objects.equal(hostName, record.hostName)) {
                return false;
            }
            if (hostAddress != null && record.hostAddress != null && !Objects.equal(hostAddress, record.hostAddress)) {
                return false;
            }
            return true;
        }

        @Override
        public String toString() {
            return Objects.toStringHelper(this)
                .add("serviceID", serviceID)
                .add("hostName", hostName)
                .add("hostAddress", hostAddress)
                .add("servicePort", servicePort)
                .add("healthy", healthy)
                .toString();
        }
    }
}
