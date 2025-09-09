package toff.novi.eindopdrachttoffshop.enums;

public enum OrderItemStatus {
    INCART("In winkelwagen"),
    PENDING("Pending"),
    ORDERED("Besteld"),
    SHIPPED("Verzonden"),
    DELIVERED("Afgeleverd"),
    CANCELLED("Geannuleerd");

    private final String displayName;

    OrderItemStatus(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public boolean isInCart() {
        return this == INCART;
    }

    public boolean isOrdered() {
        return this == ORDERED;
    }

    public boolean isCompleted() {
        return this == DELIVERED;
    }

    public boolean isCancelled() {
        return this == CANCELLED;
    }

    @Override
    public String toString() {
        return displayName;
    }
}