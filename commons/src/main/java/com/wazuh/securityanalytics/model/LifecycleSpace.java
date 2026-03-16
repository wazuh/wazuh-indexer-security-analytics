package com.wazuh.securityanalytics.model;

/**
 * Enum representing the different lifecycle spaces for security analytics entities.
 */
public enum LifecycleSpace {
    DRAFT,
    TEST,
    CUSTOM,
    STANDARD;

    @Override
    public String toString() {
        return name().toLowerCase();
    }

    /**
     * Returns whether this space allows user mutations.
     * @return true for DRAFT, TEST, CUSTOM; false for STANDARD
     */
    public boolean isUserMutable() {
        return this != STANDARD;
    }

    /**
     * Returns whether this space is valid for creation operations.
     * @return true for DRAFT and STANDARD only
     */
    public boolean isValidForCreation() {
        return this == DRAFT || this == STANDARD;
    }

    /**
     * Parse a lifecycle space from string representation.
     * @param value the string value to parse
     * @return the parsed LifecycleSpace
     * @throws IllegalArgumentException if the value is not a known space
     */
    public static LifecycleSpace fromString(String value) {
        if (value == null) {
            throw new IllegalArgumentException("LifecycleSpace value cannot be null");
        }
        try {
            return valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown LifecycleSpace: " + value);
        }
    }

    /**
     * Returns the source representation for this space.
     * @return "Sigma" for STANDARD, capitalized name for others
     */
    public String asSource() {
        if (this == STANDARD) {
            return "Sigma";
        }
        return name().substring(0, 1).toUpperCase() + name().substring(1).toLowerCase();
    }
}