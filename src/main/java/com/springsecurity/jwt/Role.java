package com.springsecurity.jwt;

public enum Role {
    USER, ADMIN;

    public static boolean isValid(String role) {
        for (Role r : Role.values()) {
            if (r.name().equalsIgnoreCase(role)) return true;
        }
        return false;
    }

    public static String getAuthority(String role) {
        switch (Role.valueOf(role)) {
            case USER -> {
                return "ROLE_USER";
            }
            case ADMIN -> {
                return "ROLE_ADMIN";
            }
        }
        throw new EnumConstantNotPresentException(Role.class, role);
    }
}
