package com.digi.connector.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public abstract class Item {

    private static final String[] invalid = { "error", "warning" };
    protected final String name;
    protected final String description;
    protected final String helpDescription;
    protected AccessType access;
    protected List<org.dom4j.Element> wrappers = new ArrayList<>();

    public enum AccessType {
        READ_ONLY, WRITE_ONLY, READ_WRITE;

        public static AccessType toAccessType(String str) throws Exception {
            try {
                return valueOf(str.toUpperCase());

            } catch (Exception e) {
                throw new Exception("Invalid access Type: " + str);
            }
        }

        public String toString() {
            return name().toLowerCase();
        }
    }

    public Item(String name, String description, String helpDescription) throws IOException {

        if (description == null) {
            throw new IOException("Missing or bad description");
        }

        for (String test: invalid) {
            if (name.equalsIgnoreCase(test)) {
                throw new IOException("Invalid name: " + name);
            }
        }
        this.name = name;
        this.description = description;
        this.helpDescription = helpDescription;
    }

    public String getRciDescription() {
        return (helpDescription == null)
            ? getDescription()
            : getDescription() + ":" + getHelpDescription();
    }

    public String getName() {
        return name;
    }

    public String getSanitizedName() {
        return name.replace('-', '_').replace(".","_fullstop_");
    }

    public String getDescription() {
        return description;
    }

    public String getHelpDescription() {
        return helpDescription;
    }

    public AccessType getAccess() {
        return access;
    }

    public void setAccess(String access) throws Exception {
        if (this.access == null)
            this.access = AccessType.toAccessType(access);
        else
            throw new Exception("Duplicate <access> keyword: " + access);
    }

    public void setCondition(final String name, final Location current, final Config config) throws Exception {
        Condition condition = config.getTable(current.getType()).conditions().get(name);
        if (condition == null) {
            for (Group.Type type : Group.Type.values()) {
                if (type != current.getType()) {
                    condition = config.getTable(type).conditions().get(name);
                    if (condition != null) break;
                }
            }
        }
        if (condition == null) {
            throw new Exception("Condition not found: " + name);
        }

        // Add each condition wrapper to the list independently
        wrappers.add(condition.wrapper(current));
    }

    public org.dom4j.Element wrapConditional(org.dom4j.Element element) {
        if (wrappers.isEmpty())
            return element;

        // Build nested structure from innermost to outermost
        // Clone each wrapper to avoid sharing DOM elements between different values
        org.dom4j.Element current = element;
        for (int i = wrappers.size() - 1; i >= 0; i--) {
            org.dom4j.Element wrapper = (org.dom4j.Element) wrappers.get(i).clone();
            wrapper.add(current);
            current = wrapper;
        }
        return current;
    }

    abstract org.dom4j.Element asElement(Integer id);
}
