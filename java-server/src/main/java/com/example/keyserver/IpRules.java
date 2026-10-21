package com.example.keyserver;

/** IPv4 CIDR 與精確位址比對；127.0.0.1 與 ::1 一律視為本機。 */
public final class IpRules {

    private IpRules() {
    }

    public static boolean matches(String rule, String ip) {
        if (rule == null || ip == null) {
            return false;
        }
        String r = rule.trim();
        String a = normalize(ip.trim());
        if (r.equals(a)) {
            return true;
        }
        if (r.equals("127.0.0.1") && (a.equals("127.0.0.1") || a.equals("::1"))) {
            return true;
        }
        int slash = r.indexOf('/');
        if (slash < 0) {
            return false;
        }
        String net = r.substring(0, slash);
        int prefix;
        try {
            prefix = Integer.parseInt(r.substring(slash + 1));
        } catch (NumberFormatException e) {
            return false;
        }
        Long n = ipv4(net);
        Long x = ipv4(a);
        if (n == null || x == null || prefix < 0 || prefix > 32) {
            return false;
        }
        long mask = prefix == 0 ? 0 : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        return (n & mask) == (x & mask);
    }

    private static String normalize(String ip) {
        if (ip.startsWith("::ffff:")) {
            return ip.substring(7);
        }
        int pct = ip.indexOf('%');
        return pct >= 0 ? ip.substring(0, pct) : ip;
    }

    private static Long ipv4(String s) {
        String[] parts = s.split("\\.");
        if (parts.length != 4) {
            return null;
        }
        long v = 0;
        for (String p : parts) {
            int o;
            try {
                o = Integer.parseInt(p);
            } catch (NumberFormatException e) {
                return null;
            }
            if (o < 0 || o > 255) {
                return null;
            }
            v = (v << 8) | o;
        }
        return v;
    }
}
