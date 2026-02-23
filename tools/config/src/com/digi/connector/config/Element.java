package com.digi.connector.config;

import java.io.IOException;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;

import com.digi.connector.config.ConfigGenerator.ItemType;

public class Element extends Item {
    public enum Type {
        STRING(1),
        MULTILINE_STRING(2),
        PASSWORD(3),
        INT32(4),
        UINT32(5),
        HEX32(6),
        X_HEX32(7),
        FLOAT(8),
        ENUM(9),
        ON_OFF(11),
        BOOLEAN(12),
        IPV4(13),
        FQDNV4(14),
        FQDNV6(15),
        LIST(17),
        MAC_ADDR(21),
        DATETIME(22),
        REF_ENUM(23),
        UINT64(25),
        HEX64(26),
        X_HEX64(27),
        BIGINT(28),
        HEXBLOB(29),
        IPV6(30),
        ;

        /* special types since enum name cannot start with 0x */
        private final static String STRING_0XHEX32 = "0X_HEX32";
        private final static String STRING_0XHEX64 = "0X_HEX64";
        private final int value;

        private Type(int value) {
            this.value = value;
        }

        public String toUpperName() {
            if (this == X_HEX32)
                return STRING_0XHEX32;
            else if (this == X_HEX64)
                return STRING_0XHEX64;
            else
                return name();
        }

        public String toLowerName() {
            return toUpperName().toLowerCase();
        }

        public int toValue() {
            return value;
        }

        public static Type toType(String str) throws Exception {
            try {
                if (str.equalsIgnoreCase(STRING_0XHEX32)) {
                    return X_HEX32;
                } else if (str.equalsIgnoreCase(STRING_0XHEX64)) {
                    return X_HEX64;
                } else {
                    return valueOf(str.toUpperCase());
                }
            } catch (Exception e) {
                throw new Exception("Invalid element Type: " + str);
            }
        }

        public String toString() {
            return toLowerName();
        }
    }

    private class RegEx {
        private boolean modified;
        private String pattern;
        private String case_sensitive;
        private String syntax;

        public RegEx() {
            modified = false;
        }

        public void setPattern(String pattern) {
            this.pattern = pattern;
            modified = true;
        }

        public void setCase(String case_sensitive) {
            this.case_sensitive = case_sensitive;
            modified = true;
        }

        public void setSyntax(String syntax) {
            this.syntax = syntax;
            modified = true;
        }

        public void validate() throws Exception {
            if (!modified)
                return;

            if ((pattern != null) && (syntax != null))
                return;

            throw new Exception("Regular expressions require both a 'pattern' and a 'syntax' keyword");
        }

        public void addAttributes(org.dom4j.Element e) {
            if (!modified)
                return;

            e.addAttribute("regex_pattern", pattern)
                .addAttribute("regex_case", Objects.toString(case_sensitive, null))
                .addAttribute("regex_syntax", syntax);
        }
    }

    private final static EnumSet<Type> supportsMinMax = EnumSet.of(
            Type.STRING,
            Type.MULTILINE_STRING,
            Type.PASSWORD,
            Type.INT32,
            Type.UINT32,
            Type.HEX32,
            Type.X_HEX32,
            Type.FLOAT,
            Type.FQDNV4,
            Type.FQDNV6,
            Type.UINT64,
            Type.HEX64,
            Type.X_HEX64,
            Type.BIGINT,
            Type.HEXBLOB,
            Type.IPV6
            );
    private final static EnumSet<Type> requiresMax = EnumSet.of(
            Type.STRING,
            Type.MULTILINE_STRING,
            Type.PASSWORD,
            Type.FQDNV4,
            Type.FQDNV6,
            Type.HEXBLOB
            );

    private static final Set<String> validOnOff = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(new String[] { "on","off" })));
    private static final Set<String> validBoolean = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(new String[] { "true","false" })));
    private static final Pattern validIPv4 = Pattern.compile("^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])[.](25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])[.](25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])[.](25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$");
    private static final Pattern validFQDN = Pattern.compile("(^[a-zA-Z]+://)?([a-z0-9-]*([.]|(::?))[a-z0-9-]*)+(:[0-9]+)?$");

    private final static Long INT32_MIN_VALUE = Long.valueOf(-2147483648L);
    private final static Long INT32_MAX_VALUE = Long.valueOf(2147483647L);
    private final static Long UINT32_MIN_VALUE = Long.valueOf(0L);
    private final static Long UINT32_MAX_VALUE = Long.valueOf(4294967295L);

    private static final BigInteger BIGINT_MIN = BigInteger.ZERO;
    private static final BigInteger BIGINT_MAX = BigInteger.ONE.shiftLeft(1024).subtract(BigInteger.ONE);

    private static final BigInteger UINT64_MIN = BigInteger.ZERO;
    private static final BigInteger UINT64_MAX = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

    private final static String VALUE_INVALID = " value invalid";
    private final static String VALUE_TOO_LOW = " value is below protocol minimum";
    private final static String VALUE_TOO_HIGH = " value is above protocol maximum";
    private final static String MIN_GREATER_THAN_MAX = "min value > max value";
    private final static String DEF_OUT_OF_RANGE = "default value is out of range";

    private Type type;
    private String min;
    private String max;
    private String def;
    private String units;
    private RegEx regex = new RegEx();

    private final LinkedList<Value> values;
    private final LinkedList<Reference> refs;

    public Element(String name, String description, String helpDescription) throws IOException {
        super(name, description, helpDescription);
        this.values = new LinkedList<Value>();
        this.refs = new LinkedList<Reference>();
    }

    public org.dom4j.Element asElement(Integer id) {
        org.dom4j.Element e = org.dom4j.DocumentHelper.createElement("element")
            .addAttribute("name", name)
            .addAttribute("desc", getRciDescription())
            .addAttribute("type", type.toString())
            .addAttribute("access", Objects.toString(access, null))
            .addAttribute("min", getValueNormalized(min))
            .addAttribute("max", getValueNormalized(max))
            .addAttribute("units", Objects.toString(units, null))
            .addAttribute("default", getValueNormalized(def));

        regex.addAttributes(e);
        e.addAttribute("bin_id", id.toString());

        switch (type) {
        case ENUM:
            for (Value value: getValues()) {
                Integer value_id = getValues().indexOf(value);

                e.add(value.asElement(value_id));
            }
            break;
        case REF_ENUM:
            for (Value value: getValues()) {
                e.add(value.asElement(null));
            }
            for (Reference ref: getRefs()) {
                e.add(ref.asElement(null));
            }
            break;
        default:
            break;
        }

        return wrapConditional(e);
    }

    private String getValueNormalized(String value) {
        if (value == null) {
            return null;
        }

        // Normalize hex values.
        if (isHexType()) {
            if (isZeroHexType()) {
                if (value.startsWith("0X") || value.startsWith("0x")) {
                    return "0x" + value.substring(2).toUpperCase();
                } else {
                    return "0x" + value.toUpperCase();
                }
            } else {
                if (value.startsWith("0X") || value.startsWith("0x")) {
                    return value.substring(2).toUpperCase();
                } else {
                    return value.toUpperCase();
                }
            }
        }

        // For other types, return the value as is
        return value;
    }

    public Type setType(String theType) throws Exception {
        if (type != null)
            throw new Exception("Duplicate <type> keyword: " + theType);

        type = Type.toType(theType);
        return type;
    }

    public void setMin(String theMin) throws Exception {
        if (min != null)
            throw new Exception("Duplicate <min> keyword: " + theMin);

        min = theMin;
    }

    public void setMax(String theMax) throws Exception {
        if (max != null)
            throw new Exception("Duplicate <max> keyword: " + theMax);

        max = theMax;
    }

    public void setDefault(String theDefault) throws Exception {
        if (def != null)
            throw new Exception("Duplicate <default> keyword: " + theDefault);

        def = theDefault;
    }

    private boolean containsValue(final String needle) {
        for (Value value: values) {
            if (value.getName().equals(needle)) {
                return true;
            }
        }
        return false;
    }

    public Value addValue(Config config, String valueName, String description, String helpDescription) throws Exception {
        if (type == null)
            throw new Exception("Missing type of enum or ref_enum on element: " + name);

        if (containsValue(valueName))
            throw new Exception("Duplicate <value>: " + valueName);

        switch (type) {
        case ENUM:
            config.nameLengthSeen(ItemType.VALUES, valueName.length());
            break;
        case REF_ENUM:
            break;
        default:
            throw new Exception("Invalid <value> for type: " + type.toLowerName());
        }

        Value value = new Value(valueName, description, helpDescription);
        values.add(value);
        return value;
    }

    private boolean containsRef(final String needle) {
        for (Reference ref: refs) {
            if (ref.getName().equals(needle)) {
                return true;
            }
        }
        return false;
    }

    public Reference addRef(Config config, String refName, String description, String helpDescription) throws Exception {
        if (type == null)
            throw new Exception("Missing type enum on element: " + name);

        if (type != Type.REF_ENUM)
            throw new Exception("Invalid <value> for type: " + type.toLowerName());

        if (containsRef(refName))
            throw new Exception("Duplicate <value>: " + refName);

        Reference ref = new Reference(refName, description, helpDescription);
        config.nameLengthSeen(ItemType.VALUES, refName.length());

        refs.add(ref);
        return ref;
    }

    private void ExceptMissingOrBad(String newValue, String name) throws IOException {
        if (newValue == null)
            throw new IOException("Missing or bad " + name);
    }

    public void setUnit(String theUnits) throws IOException {
        ExceptMissingOrBad(theUnits, "units");
        if (units != null)
            throw new IOException("Duplicate " + name + ": " + theUnits);
        this.units = theUnits;
    }

    public void setRegexPattern(String thePattern) throws IOException {
        ExceptMissingOrBad(thePattern, "regex pattern");
        try {
            Pattern.compile(thePattern);
            regex.setPattern(thePattern);
        } catch (PatternSyntaxException e) {
            throw new IOException("Invalid regex pattern: " + e.getMessage());
        }
    }

    public void setRegexCase(String theCase) throws IOException {
        ExceptMissingOrBad(theCase, "regex case");
        regex.setCase(theCase);
    }

    public void setRegexSyntax(String theSyntax) throws IOException {
        ExceptMissingOrBad(theSyntax, "regex syntax");
        regex.setSyntax(theSyntax);
    }

    public Type getType() {
        return type;
    }

    public String getMin() {
        return min;
    }

    public String getMax() {
        return max;
    }

    public String getDefault() {
        return def;
    }

    private int getValueIndex(String needle) {
        int index = 0;
        for (Value value: values) {
            if (value.getName().equals(needle)) {
                return index;
            }
            index += 1;
        }

        return -1;
    }

    public String getDefaultValue() {
        switch (type) {
        case STRING:
        case MULTILINE_STRING:
        case PASSWORD:
        case IPV4:
        case FQDNV4:
        case FQDNV6:
        case MAC_ADDR:
        case DATETIME:
        case REF_ENUM:
            return Code.quoted(def);

        case INT32:
        case UINT32:
        case HEX32:
        case X_HEX32:
        case FLOAT:
        case UINT64:
        case HEX64:
        case X_HEX64:
        case BIGINT:
        case HEXBLOB:
            return def;

        case ENUM:
        {
            int index = getValueIndex(def);
            if (index >= 0) {
                  return String.valueOf(index);
            }

            assert false: "default value not found";
            return null;
        }

        case ON_OFF:
        case BOOLEAN:
            return "connector_" + def;

        case LIST:
            assert false: "list should not have a default";
            return null;

        default:
            assert false: "unexpected default case";
            return null;
        }
    }

    public String getUnit() {
        return units;
    }

    public LinkedList<Value> getValues() {
        return values;
    }

    public LinkedList<Reference> getRefs() {
        return refs;
    }

    private Float toFloat(String string, Float def, String which) throws Exception {
        if (string == null)
            return def;

        Float value;
        try {
            value = Float.valueOf(string);
        } catch (NumberFormatException e) {
            throw new Exception(which + VALUE_INVALID);
        }

        if (value.isNaN()) {
        throw new Exception(which + VALUE_INVALID);
        }

        return value;
    }

    private Long toLong(String string, Long min, Long max, Long def, String which) throws Exception {
        if (string == null)
            return def;

        boolean is_hex = string.startsWith("0x");
        String trimmed =  is_hex ? string.substring(2) : string;
        int radix = is_hex ? 16 : 10;

        try {
            Long value = Long.valueOf(trimmed, radix);
            if (value < min) {
                throw new Exception(which + VALUE_TOO_LOW);
            }

            if (value > max) {
                throw new Exception(which + VALUE_TOO_HIGH);
            }
            return value;
        } catch (NumberFormatException e) {
            throw new Exception(which + VALUE_INVALID);
        }
    }

    private boolean isHexType() {
        return type == Type.HEX32 || type == Type.X_HEX32 || type == Type.HEXBLOB || type == Type.HEX64 || type == Type.X_HEX64;
    }

    private boolean isZeroHexType() {
        return type == Type.X_HEX32 || type == Type.X_HEX64;
    }

    private BigInteger toBigInteger(String string, BigInteger min, BigInteger max, BigInteger def, String which) throws Exception {
        if (string == null)
            return def;

        boolean has_0x_prefix = string.startsWith("0x") || string.startsWith("0X");
        boolean is_hex = has_0x_prefix || isHexType();
        String trimmed = has_0x_prefix ? string.substring(2).trim() : string.trim();
        int radix = is_hex ? 16 : 10;

        try {
            BigInteger value = new BigInteger(trimmed, radix);

            if (value.compareTo(min) < 0) {
                throw new Exception(which + VALUE_TOO_LOW);
            }

            if (value.compareTo(max) > 0) {
                throw new Exception(which + VALUE_TOO_HIGH);
            }
            return value;
        } catch (NumberFormatException e) {
            throw new Exception(which + VALUE_INVALID);
        }
    }

    private void validateIpV4() throws Exception {
        if (validIPv4.matcher(def) == null) {
            throw new Exception("invalid IPv4 address");
        }
    }

    private void validateFQDN(Type type) throws Exception {
        if (validFQDN.matcher(def) == null) {
            throw new Exception("invalid FQDN address");
        }
    }

    public void validate() throws Exception {
        if (type == null) {
            throw new Exception("Missing <type>");
        }

        if (!supportsMinMax.contains(type)) {
            if (min != null) {
                throw new Exception("min is not supported");
            }

            if (max != null) {
                throw new Exception("max is not supported");
            }
        }

        if (requiresMax.contains(type) && !this.access.equals(AccessType.READ_ONLY) && max == null) {
            throw new Exception("max is required");
        }

        regex.validate();

        switch (type) {
        case ENUM:
            if (values.isEmpty()) {
                throw new Exception("No values found for enum type");
            }

            if ((def != null) && (getValueIndex(def) == -1)) {
                throw new Exception("default enumeration value not found");
            }
            break;

        case REF_ENUM:
            if (values.isEmpty() && refs.isEmpty()) {
                throw new Exception("No values or references found for ref_enum type");
            }

            if (def != null) {
                boolean found = (getValueIndex(def) != -1);

                if (!found) {
                    for (Reference ref: refs) {
                        found = def.startsWith(ref.getName());
                           if (found) {
                            break;
                        }
                    }
                }
                if (!found) {
                    throw new Exception("default enumeration value not found");
                }
            }
            break;

        case ON_OFF:
            if ((def != null) && !validOnOff.contains(def)) {
                throw new Exception("Bad default on_off value");
            }
            break;

        case BOOLEAN:
            if ((def != null) && !validBoolean.contains(def)) {
                throw new Exception("Bad default boolean value");
            }
            break;

        case IPV4:
            if (def != null) {
                validateIpV4();
            }
            break;

        case LIST:
            if (def != null) {
                throw new Exception("Default value is invalid for <list>");
            }
            break;

        case MAC_ADDR:
            if (def != null) {
                throw new Exception("Default value is unsupported for mac_addr");
            }
            break;

        case DATETIME:
            if (def != null) {
                throw new Exception("Default value is unsupported for datetime");
            }
            break;

        case FLOAT:
            {
                Float minValue = toFloat(min, -Float.MAX_VALUE, "min");
                Float maxValue = toFloat(max, Float.MAX_VALUE, "max");
                if (minValue > maxValue) {
                    throw new Exception(MIN_GREATER_THAN_MAX);
                }

                if (def != null) {
                    Float defValue = toFloat(def, null, "default");
                    assert defValue != null;

                    boolean good = (defValue >= minValue) && (defValue <= maxValue);
                    if (!good) {
                        throw new Exception(DEF_OUT_OF_RANGE);
                    }
                }
                break;
            }

        case INT32:
            {
                Long minValue = toLong(min, INT32_MIN_VALUE, INT32_MAX_VALUE, INT32_MIN_VALUE, "min");
                Long maxValue = toLong(max, INT32_MIN_VALUE, INT32_MAX_VALUE, INT32_MAX_VALUE, "max");
                if (minValue > maxValue) {
                    throw new Exception(MIN_GREATER_THAN_MAX);
                }

                if (def != null) {
                    Long defValue = toLong(def, INT32_MIN_VALUE, INT32_MAX_VALUE, null, "default");
                    assert defValue != null;

                    boolean good = (defValue >= minValue) && (defValue <= maxValue);
                    if (!good) {
                        throw new Exception(DEF_OUT_OF_RANGE);
                    }
                }
                break;
            }
        case UINT32:
        case HEX32:
        case X_HEX32:
            {
                Long minValue = toLong(min, UINT32_MIN_VALUE, UINT32_MAX_VALUE, UINT32_MIN_VALUE, "min");
                Long maxValue = toLong(max, UINT32_MIN_VALUE, UINT32_MAX_VALUE, UINT32_MAX_VALUE, "max");
                if (minValue > maxValue) {
                    throw new Exception(MIN_GREATER_THAN_MAX);
                }

                if (def != null) {
                    Long defValue = toLong(def, UINT32_MIN_VALUE , UINT32_MAX_VALUE, null, "default");
                    assert defValue != null;

                    boolean good = (defValue >= minValue) && (defValue <= maxValue);
                    if (!good) {
                        throw new Exception(DEF_OUT_OF_RANGE);
                    }
                }
                break;
            }
        case UINT64:
        case HEX64:
        case X_HEX64:
            {
                BigInteger minValue = toBigInteger(min, UINT64_MIN, UINT64_MAX, UINT64_MIN, "min");
                BigInteger maxValue = toBigInteger(max, UINT64_MIN, UINT64_MAX, UINT64_MAX, "max");
                if (minValue.compareTo(maxValue) > 0) {
                    throw new Exception(MIN_GREATER_THAN_MAX);
                }

                if (def != null) {
                    BigInteger defValue = toBigInteger(def, UINT64_MIN, UINT64_MAX, null, "default");
                    assert defValue != null;

                    boolean good = (defValue.compareTo(minValue) >= 0) && (defValue.compareTo(maxValue) <= 0);
                    if (!good) {
                        throw new Exception(DEF_OUT_OF_RANGE);
                    }
                }
                break;
            }
        case BIGINT:
            {
                BigInteger minValue = toBigInteger(min, BIGINT_MIN, BIGINT_MAX, BIGINT_MIN, "min");
                BigInteger maxValue = toBigInteger(max, BIGINT_MIN, BIGINT_MAX, BIGINT_MAX, "max");
                if (minValue.compareTo(maxValue) > 0) {
                    throw new Exception(MIN_GREATER_THAN_MAX);
                }

                if (def != null) {
                    BigInteger defValue = toBigInteger(def, BIGINT_MIN, BIGINT_MAX, null, "default");
                    assert defValue != null;

                    boolean good = (defValue.compareTo(minValue) >= 0) && (defValue.compareTo(maxValue) <= 0);
                    if (!good) {
                        throw new Exception(DEF_OUT_OF_RANGE);
                    }
                }
                break;
            }
        case HEXBLOB:
            {
                Long minValue = toLong(min, INT32_MIN_VALUE, INT32_MAX_VALUE, INT32_MIN_VALUE, "min");
                Long maxValue = toLong(max, INT32_MIN_VALUE, INT32_MAX_VALUE, INT32_MAX_VALUE, "max");
                if (minValue > maxValue) {
                    throw new Exception(MIN_GREATER_THAN_MAX);
                }

                if (def != null) {
                    Long defValueLength = (long) def.replace("0x", "").replace("0X", "").length();
                    // Do not check min length for HEXBLOB. Problem arises when default value is "0x" or "0X"
                    // and min is set to 1 byte.
                    if (defValueLength / 2 < 0 || defValueLength / 2 > maxValue) {
                        throw new Exception(DEF_OUT_OF_RANGE);
                    }
                }
                break;
            }
        default:
            {
                if (supportsMinMax.contains(type)) {
                    BigInteger minValue = toBigInteger(min, BIGINT_MIN, BIGINT_MAX, BIGINT_MIN, "min");
                    BigInteger maxValue = toBigInteger(max, BIGINT_MIN, BIGINT_MAX, BIGINT_MAX , "max");
                    if (minValue.compareTo(maxValue) > 0) {
                        throw new Exception(MIN_GREATER_THAN_MAX);
                    }

                    switch (type) {
                    case STRING:
                    case MULTILINE_STRING:
                    case PASSWORD:
                        if (def != null) {
                            Long length = (long) def.length();
                            BigInteger lengthBI = BigInteger.valueOf(length);

                            boolean good = (lengthBI.compareTo(minValue) >= 0) && (lengthBI.compareTo(maxValue) <= 0);
                            if (!good) {
                                throw new Exception(DEF_OUT_OF_RANGE);
                            }
                        }
                        break;

                    case FQDNV4:
                    case FQDNV6:
                        if (def != null) {
                            validateFQDN(type);
                        }
                        break;

                    default:
                        assert false: "unexpected type in switch";
                    }
                }
                break;
            }
        }
    }

    public Item find(final String name) throws NoSuchElementException {
        throw new NoSuchElementException();
    }
}
