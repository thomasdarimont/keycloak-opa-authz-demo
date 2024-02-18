package com.thomasdarimont.keycloak.accessmgmt;

import java.util.Map;

public class AccessDecision {

    public enum Outcome {
        ALLOWED, DENIED
    }

    private final Outcome outcome;

    private final Map<String, Object> details;

    public AccessDecision(boolean allow, Map<String, Object> details) {
        this(allow ? Outcome.ALLOWED : Outcome.DENIED, details);
    }

    public AccessDecision(Outcome outcome, Map<String, Object> details) {
        this.outcome = outcome;
        this.details = details;
    }

    public Outcome getOutcome() {
        return outcome;
    }

    public Map<String, Object> getDetails() {
        return details;
    }

    public boolean isAllowed() {
        return outcome == Outcome.ALLOWED;
    }

    public boolean isDenied() {
        return outcome == Outcome.DENIED;
    }

    @Override
    public String toString() {
        return "AccessDecision{" +
                "outcome=" + outcome +
                ", details=" + details +
                '}';
    }
}
