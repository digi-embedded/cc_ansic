package com.digi.connector.config;

import java.util.LinkedHashMap;

public class RciStrings {

    protected final LinkedHashMap<String, String> rciStrings = new LinkedHashMap<String, String>();

    public RciStrings(String[] strPairs)
    {
        for (int i = 0; i < strPairs.length; i += 2) {
            rciStrings.put(strPairs[i], strPairs[i+1]);
        }
    }

    public RciStrings() {
    }

    public void addStrings(String key, String value) {
        rciStrings.put(key, value);
    }

    public int size() {
        return rciStrings.size();
    }

    public LinkedHashMap<String, String> getStrings() {
        return rciStrings;
    }

}
