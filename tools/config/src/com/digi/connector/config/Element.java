package com.digi.connector.config;

import java.io.IOException;
import java.util.LinkedList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Element extends Item {

    private final static int INT32_MIN_VALUE = -2147483648;
    private final static int INT32_MAX_VALUE = 2147483647;
    private final static long UINT32_MAX_VALUE = 4294967295L;

    private final static String BAD_MISSING_MIN_VALUE = "Bad or missing min value!";
    private final static String BAD_MISSING_MAX_VALUE = "Bad or missing max value!";

    private String type;
    private String min;
    private String max;
    private String units;
    private final LinkedList<ValueStruct> values;

    private static boolean floatLimit;

    public enum ElementType {
        STRING(true, 1),
        MULTILINE_STRING(true, 2),
        PASSWORD(true, 3),
        INT32(true, 4),
        UINT32(true, 5),
        HEX32(true, 6),
        X_HEX32(true, 7),
        FLOAT(true, 8),
        ENUM(false, 9),
        ON_OFF(false, 11),
        BOOLEAN(false, 12),
        IPV4(false, 13),
        FQDNV4(true, 14),
        FQDNV6(true, 15),
        LIST(false, 17),
        MAC_ADDR(false, 21),
        DATETIME(false, 22);

        /* special type since string cannot start 0x (zero) */
        private final static String STRING_0XHEX32 = "0x_hex32";

        private final boolean minMaxSupport;
        private final int value;
        private boolean typeAvailable;

        private ElementType(boolean support, int value) {
            this.minMaxSupport = support;
            this.value = value;
        }

        public boolean minMaxSupport() {
            return minMaxSupport;
        }

        public void set() {
            typeAvailable = true;
        }

        public boolean isSet() {
            return typeAvailable;
        }

        public String toName() {
            if (this == X_HEX32)
                return STRING_0XHEX32;
            else
                return name();
        }

        public int toValue() {
            return value;
        }

        public static ElementType toElementType(String str) throws Exception {
            try {
               /* special case for 0xhex32 type */
                if (str.equalsIgnoreCase(STRING_0XHEX32) == true) {
                    return valueOf(str.toUpperCase().substring(1));
                } else {
                    return valueOf(str.toUpperCase());
                }
            } catch (Exception e) {
                throw new Exception("Invalid element Type: " + str);
            }

        }

    }

    public Element(String name, String description, String helpDescription) throws IOException {
        super(name, description, helpDescription);
        this.values = new LinkedList<ValueStruct>();
    }

    public String toString(int id) {
        String descriptor = String.format("<element name=`%s` desc=`%s` type=`%s`", name, toRciDescription(), type);

        if (access != null)
            descriptor += String.format(" access=`%s`", access);
        if (min != null)
            descriptor += String.format(" min=`%s`", min);
        if (max != null)
            descriptor += String.format(" max=`%s`", max);
        if (units != null)
            descriptor += String.format(" units=`%s`", units);

        descriptor += String.format(" bin_id=`%d`", id);

        try {

            if (ElementType.toElementType(type) == ElementType.ENUM)
                descriptor += ">";
            else
                descriptor += " />";

        } catch (Exception e) {
            e.printStackTrace();
        }

        descriptor = descriptor.replace('`', '"');

        return descriptor;
    }

    public static boolean includeFloatLimit() {
        return floatLimit;
    }

    public void setType(String theType) throws Exception {
        if (type == null)
            type = theType;
        else
            throw new Exception("Duplicate <type> keyword: " + theType);

        ElementType elementType = ElementType.toElementType(type);

        elementType.set();
    }

    public void setMin(String theMin) throws Exception {
        if (min == null)
            min = theMin;
        else
            throw new Exception("Duplicate <min> keyword: " + theMin);
    }

    public void setMax(String theMax) throws Exception {
        if (max == null)
            max = theMax;
        else
            throw new Exception("Duplicate <max> keyword: " + theMax);
    }

    public void addValue(String valueName, String description,
            String helpDescription) throws Exception {
        if (type == null) {
            throw new Exception("Missing type enum on element: " + name);
        } else if (ElementType.toElementType(type) == ElementType.ENUM) {

            if (values.contains(valueName)) {
                throw new Exception("Duplicate <value>: " + valueName);
            }
            ValueStruct value = new ValueStruct(valueName, description,
                    helpDescription);
            values.add(value);
        } else {
            throw new Exception("Invalid <value> for type: " + type);
        }
    }

    public void setUnit(String theUnit) throws IOException {
        if (theUnit == null)
            throw new IOException("Missing or bad units description!");
        else if (units != null)
            throw new IOException("Duplicate units: " + theUnit);
        else
            units = theUnit;
    }

    public String getType() {
        return type;
    }

    public String getMin() {
        return min;
    }

    public String getMax() {
        return max;
    }

    public String getUnit() {
        return units;
    }

    public LinkedList<ValueStruct> getValues() {
        return values;
    }

    public void validate() throws Exception {
        try {
            ElementType etype = ElementType.toElementType(type);

            if (type == null) {
                throw new Exception("Missing <type>!");
            }

            if (!etype.minMaxSupport() && (min != null || max != null)) {
                throw new Exception("\"" + type + "\" type should not have <min/max>!");
            }

            switch (etype) {
            case ENUM:
                if (values.isEmpty()) {
                    throw new Exception("Missing <value>!");
                }
                break;

            case FLOAT:
                if (!isValidFloat(min)) {
                    throw new Exception(BAD_MISSING_MIN_VALUE);
                }

                if (!isValidFloat(max)) {
                    throw new Exception(BAD_MISSING_MAX_VALUE);
                }

                if ((min != null) && (max != null)) {
                    float minValue = Float.parseFloat(min);
                    float maxValue = Float.parseFloat(max);

                    if (minValue > maxValue) {
                        throw new Exception("Error min value > max value!");
                    }
                }

                if (((min == null) || (max == null))
                        && ((min != null) || (max != null))) {
                    floatLimit = true;
                }
                break;

            case X_HEX32:
            case HEX32:
                boolean prefix = false;
                if (etype == ElementType.X_HEX32) {
                    prefix = true;
                }
                if (!isValidHex(min, prefix)) {
                    throw new Exception(BAD_MISSING_MIN_VALUE);
                }
                if (!isValidHex(max, prefix)) {
                    throw new Exception(BAD_MISSING_MAX_VALUE);
                }
                if ((min != null) && (max != null)) {
                    int index = 0;
                    if (prefix) {
                        index = 2;
                    }

                    int minValue = Integer.parseInt(min.substring(index), 16);
                    int maxValue = Integer.parseInt(max.substring(index), 16);

                    if (minValue > maxValue) {
                        throw new Exception("Error min value > max value!");
                    }
                }
                break;

            default:
                long minValue = (etype == Element.ElementType.INT32) ? INT32_MIN_VALUE
                        : 0;
                long maxValue = (etype == Element.ElementType.INT32) ? INT32_MAX_VALUE
                        : UINT32_MAX_VALUE;

                if (min != null) {
                    try {
                        minValue = Long.parseLong(min);
                    } catch (NumberFormatException e) {
                        throw new Exception(BAD_MISSING_MIN_VALUE);
                    }
                }
                if (max != null) {
                    try {
                        maxValue = Long.parseLong(max);
                    } catch (NumberFormatException e) {
                        throw new Exception(BAD_MISSING_MAX_VALUE);
                    }

                }

                if (etype != Element.ElementType.INT32) {
                    if ((minValue < 0) || (maxValue < 0)) {
                        throw new Exception(
                                "Invalid min or max value for type: "
                                        + etype.toString().toLowerCase());
                    }
                    if ((minValue > UINT32_MAX_VALUE)
                     || (maxValue > UINT32_MAX_VALUE)) {
                        throw new Exception(
                                "Overflow min or max value for type: "
                                        + etype.toString().toLowerCase());
                    }
                } else if ((minValue < INT32_MIN_VALUE)
                        || (minValue > INT32_MAX_VALUE)
                        || (maxValue < INT32_MIN_VALUE)
                        || (maxValue > INT32_MAX_VALUE)) {
                    throw new Exception("Overflow min or max value for type: "
                            + etype.toString().toLowerCase());
                }

                if (minValue > maxValue) {
                    throw new Exception("Error min value > max value!");
                }

                break;
            }

            if (etype != ElementType.ENUM && !values.isEmpty()) {
                throw new Exception("Invalid <value> for type: " + type);
            }

        } catch (Exception e) {
            throw e;
        }
    }

    private boolean isValidFloat(String str) {
        boolean isValid = true;
        if (str != null) {
            try {
                Float.parseFloat(str);
            } catch (NumberFormatException e) {
                isValid = false;
            }
        }
        return isValid;
    }

    private final static String HEXCOMPILE = "[A-Fa-f0-9]{1,8}";
    private final static String PREFIXHEXCOMPILE = "0x[A-Fa-f0-9]{1,8}";

    private static boolean isValidHex(String str, boolean prefix_0x) {
        boolean isValid = true;

        String compile = HEXCOMPILE;
        if (prefix_0x) {
            compile = PREFIXHEXCOMPILE;
        }

        Pattern HEXPATTERN = Pattern.compile(compile);

        if (str != null) {
            Matcher m = HEXPATTERN.matcher(str);
            isValid = m.matches();
        }

        return isValid;
    }

}
