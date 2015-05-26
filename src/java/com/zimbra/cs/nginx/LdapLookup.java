/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2011, 2013, 2014 Zimbra, Inc.
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
import java.util.Set;

import org.python.google.common.collect.Maps;

import com.zimbra.common.service.ServiceException;
import com.zimbra.cs.account.Config;
import com.zimbra.cs.ldap.ILdapContext;
import com.zimbra.cs.ldap.ZAttributes;
import com.zimbra.cs.ldap.ZLdapFilter;
import com.zimbra.cs.ldap.ZLdapFilterFactory.FilterId;
import com.zimbra.cs.nginx.NginxLookupExtension.NginxLookupException;

public interface LdapLookup {

    static class SearchDirResult {
        String dn;
        String entryCSN;
        // key of the map is one of the zimbraReverseProvyXXXAttribute
        // value is the attr value of the attribute stored in the corresponding zimbraReverseProvyXXXAttribute
        final private Map<String, String> configuredAttrs = Maps.newHashMap();

        // key of the map the ldap attribute name
        // value is ldap attribute value
        final private Map<String, String> extraAttrs = Maps.newHashMap();

        public SearchDirResult(String distinguishedName, String entryCSN) {
            this.dn = distinguishedName;
            this.entryCSN = entryCSN;
        }

        /** @return Directory distinguished name */
        public String getDN() {
            return dn;
        }

        /** @return EntryCSN for directory entry */
        public String getEntryCSN() {
            return entryCSN;
        }

        public void addConfiguredAttr(String key, String value) {
            configuredAttrs.put(key, value);
        }

        public String getConfiguredAttr(String key) {
            return configuredAttrs.get(key);
        }

        public void addExtraAttr(String key, String value) {
            extraAttrs.put(key, value);
        }

        public String getExtraAttr(String key) {
            return extraAttrs.get(key);
        }
    }

    public static class SearchDirMatch {
        String dn;
        ZAttributes ldapAttrs;
        public SearchDirMatch(String distinguishedName, ZAttributes attrs) {
            dn = distinguishedName;
            ldapAttrs = attrs;
        }

        /** @return Directory distinguished name */
        public String getDN() {
            return dn;
        }

        public String getEntryCSN() {
            return ldapAttrs.getEntryCSN();
        }

        public String getAttr(String attrName) throws NginxLookupException {
            try {
                return ldapAttrs.getAttrString(attrName);
            } catch (ServiceException e) {
                throw new NginxLookupException("unable to search LDAP", e);
            }
        }
    }

    public ILdapContext getLdapContext() throws ServiceException;

    public void closeLdapContext(ILdapContext ldapContext);

    /**
     *
     * @param zlc
     * @param returnAttrs
     * @param config
     * @param query                the query, use as is
     * @param searchBaseConfigAttr global config attribute name that contains the search base
     * @return first matching result
     * @throws NginxLookupException
     */
    public SearchDirMatch searchDirForEntry(ILdapContext ldapContext, String[] returnAttrs,
            Config config, ZLdapFilter filter, String searchBaseConfigAttr)
    throws NginxLookupException;

    /**
     *
     * @param zlc
     * @param returnAttrs
     * @param config
     * @param queryTemplate
     * @param searchBase
     * @param templateKey
     * @param templateVal
     * @param attrs       key of the map is one of the zimbraReverseProxyXXXAttribute
     *                    value of the map is if this attribute is required
     * @param extraAttrs  set of attribute names to return
     * @return first matching result
     * @throws NginxLookupException
     */
    public SearchDirResult searchDirectory(ILdapContext ldapContext, String[] returnAttrs,
            Config config, FilterId filterId, String queryTemplate, String searchBase,
            String templateKey, String templateVal, Map<String, Boolean> attrs, Set<String> extraAttrs)
    throws NginxLookupException;

}
