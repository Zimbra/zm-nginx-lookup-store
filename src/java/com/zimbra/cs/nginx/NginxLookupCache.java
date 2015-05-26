/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2008, 2009, 2010, 2012, 2013, 2014 Zimbra, Inc.
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

import java.util.Map;

import com.zimbra.common.service.ServiceException;
import com.zimbra.common.util.MapUtil;
import com.zimbra.common.util.ZimbraLog;
import com.zimbra.cs.account.ldap.LdapCache;
import com.zimbra.cs.account.ldap.LdapHelper;
import com.zimbra.cs.ldap.LdapClient;
import com.zimbra.cs.ldap.LdapServerType;
import com.zimbra.cs.ldap.LdapUsage;
import com.zimbra.cs.ldap.ZLdapContext;

public class NginxLookupCache<E extends LookupEntry> {

    private final Map<String, CacheEntry<E>> mCache;
    private final long refreshTTL;
    private final FreshnessChecker freshnessChecker;

    static class CacheEntry<E extends LookupEntry> {
        long lifetime;
        public long lastFreshCheckTime;
        E entry;
        CacheEntry(E entry, long expires) {
            this.entry = entry;
            lifetime = System.currentTimeMillis() + expires;
            lastFreshCheckTime = System.currentTimeMillis();
            lifetime = lastFreshCheckTime + expires;
        }

        boolean isStale() {
            return lifetime < System.currentTimeMillis();
        }
    }

    static class FreshnessChecker {
        private final LdapHelper helper;
        public FreshnessChecker(LdapHelper helper) {
            this.helper = helper;
        }

        public boolean isStale(LookupEntry entry) {
            ZLdapContext zlc = null;
            try {
                zlc = LdapClient.getContext(LdapServerType.REPLICA, LdapUsage.COMPARE);
                if (LdapCache.isEntryStale(entry.getDn(), entry.getEntryCSN(), helper, zlc)) {
                    return true;
                }
                String entryCSNforConfig = entry.getConfigEntryCSN();
                if (null != entryCSNforConfig) {
                    String configDN  = helper.getProv().getDIT().configDN();
                    if (null != configDN) {
                        if (LdapCache.isEntryStale(configDN, entryCSNforConfig, helper, zlc)) {
                            return true;
                        }
                    }
                }
                return false;
            } catch (ServiceException se) {
                ZimbraLog.ldap.debug("Nginx FreshnessChecker can't check Config %s - assume stale", entry.getDn(), se);
                return true;
            } finally {
                LdapClient.closeContext(zlc);
            }
        }
    }

    /**
     * @param maxItems
     * @param refreshTTL
     */
    public NginxLookupCache(int maxItems, long refreshTTL, FreshnessChecker freshnessChecker) {
        mCache = MapUtil.newLruMap(maxItems);
        this.refreshTTL = refreshTTL;
        this.freshnessChecker = freshnessChecker;
    }

    public synchronized void clear() {
        mCache.clear();
    }

    public synchronized void remove(String name) {
        mCache.remove(name);
    }

    public synchronized void remove(E entry) {
        if (entry != null) {
            mCache.remove(entry.getKey());
        }
    }

    public synchronized void put(E entry) {
        if (entry != null) {
            CacheEntry<E> cacheEntry = new CacheEntry<E>(entry, refreshTTL);
            mCache.put(entry.getKey(), cacheEntry);
        }
    }

    /*
    public synchronized void put(List<E> entries, boolean clear) {
        if (entries != null) {
            if (clear) clear();
            for (E e: entries)
                put(e);
        }
    }
    */

    public synchronized E get(String key) {
        CacheEntry<E> ce = mCache.get(key);
        if (ce != null) {
            if ((refreshTTL != 0 && ce.isStale()) || staleByFreshness(ce)) {
                remove(ce.entry);
                return null;
            } else {
                return ce.entry;
            }
        } else {
            return null;
        }
    }

    private boolean staleByFreshness(CacheEntry<E> ce) {
        if (freshnessChecker == null) {
            return false;
        }
        long now = System.currentTimeMillis();
        if (now < (ce.lastFreshCheckTime + LdapCache.ldapCacheFreshnessCheckLimitMs())) {
            return false; // Avoid checking too often
        }
        boolean stale = freshnessChecker.isStale(ce.entry);
        ce.lastFreshCheckTime = now;
        return stale;
    }
}
