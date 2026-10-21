package com.example.keyserver;

import java.util.Locale;

public enum Role {
    VIEWER(1), OPERATOR(2), ADMIN(3);

    private final int level;

    Role(int level) {
        this.level = level;
    }

    public int level() {
        return level;
    }

    public boolean atLeast(Role other) {
        return this.level >= other.level;
    }

    public static Role parse(String s, Role fallback) {
        if (s == null) {
            return fallback;
        }
        try {
            return valueOf(s.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return fallback;
        }
    }
}
