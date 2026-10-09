package com.jobshield;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Minimal JSON parser/serializer (zero dependencies). Supports objects, arrays, strings, numbers, booleans, null. */
public final class Json {
    private Json() {}

    public static Object parse(String s) {
        Parser p = new Parser(s);
        Object v = p.parseValue();
        p.skipWs();
        if (!p.eof()) throw new IllegalArgumentException("Trailing JSON at position " + p.pos);
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Object v) {
        return v instanceof Map ? (Map<String, Object>) v : null;
    }

    @SuppressWarnings("unchecked")
    public static List<Object> arr(Object v) {
        return v instanceof List ? (List<Object>) v : null;
    }

    public static String str(Object v) {
        return v instanceof String ? (String) v : null;
    }

    public static String strOr(Map<String, Object> m, String key, String def) {
        Object v = m == null ? null : m.get(key);
        return v instanceof String ? (String) v : def;
    }

    public static String stringify(Object v) {
        StringBuilder sb = new StringBuilder();
        write(v, sb);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(Object v, StringBuilder sb) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof String s) { writeStr(s, sb); return; }
        if (v instanceof Boolean || v instanceof Number) { sb.append(v.toString()); return; }
        if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) v).entrySet()) {
                if (!first) sb.append(',');
                first = false;
                writeStr(e.getKey(), sb);
                sb.append(':');
                write(e.getValue(), sb);
            }
            sb.append('}');
            return;
        }
        if (v instanceof List) {
            sb.append('[');
            boolean first = true;
            for (Object e : (List<Object>) v) {
                if (!first) sb.append(',');
                first = false;
                write(e, sb);
            }
            sb.append(']');
            return;
        }
        writeStr(String.valueOf(v), sb);
    }

    private static void writeStr(String s, StringBuilder sb) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        sb.append('"');
    }

    private static final class Parser {
        final String s; int pos;
        Parser(String s) { this.s = s == null ? "" : s; }
        boolean eof() { return pos >= s.length(); }
        void skipWs() { while (pos < s.length()) { char c = s.charAt(pos); if (c==' '||c=='\t'||c=='\n'||c=='\r') pos++; else break; } }
        Object parseValue() {
            skipWs();
            if (eof()) throw new IllegalArgumentException("Unexpected end of JSON");
            char c = s.charAt(pos);
            return switch (c) {
                case '{' -> parseObj();
                case '[' -> parseArr();
                case '"' -> parseStr();
                case 't' -> { expect("true"); yield Boolean.TRUE; }
                case 'f' -> { expect("false"); yield Boolean.FALSE; }
                case 'n' -> { expect("null"); yield null; }
                default -> parseNum();
            };
        }
        void expect(String lit) {
            if (s.startsWith(lit, pos)) pos += lit.length();
            else throw new IllegalArgumentException("Expected " + lit + " at " + pos);
        }
        Map<String, Object> parseObj() {
            Map<String, Object> m = new LinkedHashMap<>();
            pos++; skipWs();
            if (!eof() && s.charAt(pos) == '}') { pos++; return m; }
            while (true) {
                skipWs();
                if (eof() || s.charAt(pos) != '"') throw new IllegalArgumentException("Expected key at " + pos);
                String k = parseStr();
                skipWs();
                if (eof() || s.charAt(pos) != ':') throw new IllegalArgumentException("Expected : at " + pos);
                pos++;
                m.put(k, parseValue());
                skipWs();
                if (eof()) throw new IllegalArgumentException("Unterminated object");
                char d = s.charAt(pos++);
                if (d == '}') break;
                if (d != ',') throw new IllegalArgumentException("Expected , or } at " + (pos-1));
            }
            return m;
        }
        List<Object> parseArr() {
            List<Object> l = new ArrayList<>();
            pos++; skipWs();
            if (!eof() && s.charAt(pos) == ']') { pos++; return l; }
            while (true) {
                l.add(parseValue());
                skipWs();
                if (eof()) throw new IllegalArgumentException("Unterminated array");
                char d = s.charAt(pos++);
                if (d == ']') break;
                if (d != ',') throw new IllegalArgumentException("Expected , or ] at " + (pos-1));
            }
            return l;
        }
        String parseStr() {
            pos++; // opening quote
            StringBuilder sb = new StringBuilder();
            while (pos < s.length()) {
                char c = s.charAt(pos++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    if (pos >= s.length()) break;
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"' -> sb.append('"');
                        case '\\' -> sb.append('\\');
                        case '/' -> sb.append('/');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'u' -> {
                            if (pos + 4 > s.length()) throw new IllegalArgumentException("Bad \\u escape");
                            sb.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                            pos += 4;
                        }
                        default -> sb.append(e);
                    }
                } else sb.append(c);
            }
            throw new IllegalArgumentException("Unterminated string");
        }
        Object parseNum() {
            int start = pos;
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if ((c>='0'&&c<='9')||c=='-'||c=='+'||c=='.'||c=='e'||c=='E') pos++;
                else break;
            }
            if (start == pos) throw new IllegalArgumentException("Unexpected char at " + pos);
            String t = s.substring(start, pos);
            try {
                if (t.contains(".") || t.contains("e") || t.contains("E")) return Double.parseDouble(t);
                try { return Long.parseLong(t); } catch (NumberFormatException ex) { return Double.parseDouble(t); }
            } catch (NumberFormatException ex) { throw new IllegalArgumentException("Bad number " + t); }
        }
    }
}
