/*
 * ***** BEGIN LICENSE BLOCK *****
 * Zimbra Collaboration Suite Server
 * Copyright (C) 2008, 2009, 2010, 2013, 2014 Zimbra, Inc.
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

public abstract class LookupEntry {
    private final String key;

    protected String dn = null;
    protected String entryCSN = null;
    protected String configEntryCSN = null;

    LookupEntry(String key, String dn, String entryCSN, String configEntryCSN) {
        this.key = key;
        this.dn = dn;
        this.entryCSN = entryCSN;
        this.configEntryCSN = configEntryCSN;
    }

    String getKey() {
        return key;
    }

    public String getDn() {
        return dn;
    }

    public String getEntryCSN() {
        return entryCSN;
    }

    public String getConfigEntryCSN() {
        return configEntryCSN;
    }
}
