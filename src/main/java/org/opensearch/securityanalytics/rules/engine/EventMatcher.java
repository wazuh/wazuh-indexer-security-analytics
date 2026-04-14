/*
 * Copyright (C) 2026, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package org.opensearch.securityanalytics.rules.engine;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.securityanalytics.rules.condition.*;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;
import org.opensearch.securityanalytics.rules.types.*;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.math.BigDecimal;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Evaluates Sigma rules against normalized events.
 *
 * <p>Takes a JSON event and a list of pre-parsed {@link SigmaRule} objects, flattens the event into
 * a dot-notation map, then evaluates each rule's detection conditions against the event fields.
 * Results are returned as a JSON string summarizing which rules matched and why.
 *
 * <p>Compiled regex patterns for wildcard matching are cached in a thread-safe {@link
 * ConcurrentHashMap} to avoid repeated compilation of the same expressions.
 */
public class EventMatcher {

    private static final Logger log = LogManager.getLogger(EventMatcher.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Cache of compiled regex patterns keyed by the original wildcard string. */
    private final Map<String, Pattern> regexCache = new ConcurrentHashMap<>();

    private static final String STATUS_SUCCESS = "success";
    private static final String STATUS_ERROR = "error";
    private static final String UNKNOWN_VALUE = "unknown";

    /** Creates a new {@code EventMatcher} instance. */
    public EventMatcher() {}

    /**
     * Evaluates a list of pre-parsed Sigma rules against a single event.
     *
     * <p>The event JSON is flattened into dot-notation keys (e.g. {@code "process.name"}) before
     * matching. Each rule's detection conditions are evaluated against the flat map, and any matching
     * rules are collected into the result.
     *
     * @param eventJson the event as a JSON string (may contain nested objects)
     * @param rules list of pre-parsed {@link SigmaRule} objects to evaluate
     * @return a JSON string containing {@code status}, {@code rules_evaluated}, {@code
     *     rules_matched}, and a {@code matches} array with details for each match
     */
    @SuppressWarnings("unchecked")
    public String evaluate(String eventJson, List<SigmaRule> rules) {
        List<Map<String, Object>> matches = new ArrayList<>();
        int rulesEvaluated = 0;
        String status = STATUS_SUCCESS;

        try {
            Map<String, Object> parsedEvent = MAPPER.readValue(eventJson, Map.class);
            Map<String, Object> flatEvent = new HashMap<>();
            flattenMapIterative(parsedEvent, flatEvent);

            for (SigmaRule sigmaRule : rules) {
                rulesEvaluated++;
                List<String> matchedConditions = new ArrayList<>();
                boolean ruleMatched;

                try {
                    ruleMatched =
                            sigmaRule.getDetection().getParsedCondition().stream()
                                    .map(
                                            condition -> {
                                                try {
                                                    return condition.parsed().getLeft();
                                                } catch (SigmaConditionError e) {
                                                    throw new IllegalStateException("Condition parse error", e);
                                                }
                                            })
                                    .filter(Objects::nonNull)
                                    .anyMatch(
                                            conditionItem ->
                                                    evaluateCondition(conditionItem, flatEvent, matchedConditions));
                } catch (IllegalStateException e) {
                    log.warn(
                            "Failed to evaluate condition for rule '{}': {}", sigmaRule.getId(), e.getMessage());
                    continue; // Skip this rule and proceed to the next
                }

                if (ruleMatched) {
                    matches.add(buildMatchEntry(sigmaRule, matchedConditions));
                }
            }
        } catch (Exception e) {
            log.error("Failed to evaluate rules against event.", e);
            status = STATUS_ERROR;
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("status", status);
        result.put("rules_evaluated", rulesEvaluated);
        result.put("rules_matched", matches.size());
        result.put("matches", matches);

        try {
            return MAPPER.writeValueAsString(result);
        } catch (Exception e) {
            return String.format(
                    "{\"status\":\"%s\",\"rules_evaluated\":0,\"rules_matched\":0,\"matches\":[]}",
                    STATUS_ERROR);
        }
    }

    /**
     * Builds a match result entry containing rule metadata and the conditions that triggered it.
     *
     * @param rule the matched {@link SigmaRule}
     * @param matchedConditions human-readable descriptions of the conditions that matched
     * @return an ordered map suitable for JSON serialization
     */
    private Map<String, Object> buildMatchEntry(SigmaRule rule, List<String> matchedConditions) {
        Map<String, Object> ruleInfo = new LinkedHashMap<>();
        ruleInfo.put("id", rule.getId() != null ? rule.getId().toString() : UNKNOWN_VALUE);
        ruleInfo.put("title", rule.getTitle() != null ? rule.getTitle() : UNKNOWN_VALUE);
        ruleInfo.put("level", rule.getLevel() != null ? rule.getLevel().toString() : UNKNOWN_VALUE);
        ruleInfo.put(
                "tags",
                rule.getTags() == null
                        ? Collections.emptyList()
                        : rule.getTags().stream()
                                .map(tag -> tag.getNamespace() + "." + tag.getName())
                                .collect(Collectors.toList()));

        Map<String, Object> match = new LinkedHashMap<>();
        match.put("rule", ruleInfo);
        match.put("matched_conditions", matchedConditions);
        return match;
    }

    /**
     * Flattens a nested map into dot-notation keys using an iterative (stack-based) approach.
     *
     * <p>For example, {@code {"process": {"name": "cmd.exe"}}} becomes {@code {"process.name":
     * "cmd.exe"}}.
     *
     * @param source the nested source map
     * @param target the flat target map to populate
     */
    @SuppressWarnings("unchecked")
    private void flattenMapIterative(Map<String, Object> source, Map<String, Object> target) {
        Deque<Map.Entry<String, Object>> stack = new ArrayDeque<>();
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            stack.push(entry);
        }

        while (!stack.isEmpty()) {
            Map.Entry<String, Object> current = stack.pop();
            String key = current.getKey();
            Object value = current.getValue();

            if (value instanceof Map) {
                Map<String, Object> nestedMap = (Map<String, Object>) value;
                for (Map.Entry<String, Object> nestedEntry : nestedMap.entrySet()) {
                    stack.push(
                            new AbstractMap.SimpleEntry<>(
                                    key + "." + nestedEntry.getKey(), nestedEntry.getValue()));
                }
            } else {
                target.put(key, value);
            }
        }
    }

    /**
     * Recursively evaluates a condition tree against the flattened event.
     *
     * <p>Handles field-equals-value expressions, keyword (value-only) expressions, and composite
     * conditions ({@code AND}, {@code OR}, {@code NOT}).
     *
     * @param item the condition node to evaluate
     * @param event the flattened event map (dot-notation keys)
     * @param matchedConditions accumulator for human-readable descriptions of matched conditions
     * @return {@code true} if the condition matches the event
     */
    private boolean evaluateCondition(
            ConditionItem item, Map<String, Object> event, List<String> matchedConditions) {

        if (item instanceof ConditionFieldEqualsValueExpression fieldExpr) {
            if (matchValue(event.get(fieldExpr.getField()), fieldExpr.getValue())) {
                matchedConditions.add(
                        fieldExpr.getField() + " matched '" + formatSigmaValue(fieldExpr.getValue()) + "'");
                return true;
            }
            return false;
        }

        if (item instanceof ConditionValueExpression valueExpr) {
            for (Map.Entry<String, Object> entry : event.entrySet()) {
                if (matchValue(entry.getValue(), valueExpr.getValue())) {
                    matchedConditions.add(entry.getKey() + " contains '" + valueExpr.getValue() + "'");
                    return true;
                }
            }
            return false;
        }

        List<ConditionItem> children =
                item.getArgs() == null
                        ? Collections.emptyList()
                        : item.getArgs().stream()
                                .filter(Either::isLeft)
                                .map(arg -> resolveConditionItem(arg.getLeft()))
                                .filter(Objects::nonNull)
                                .toList();

        if (item instanceof ConditionOR) {
            return children.stream()
                    .anyMatch(child -> evaluateCondition(child, event, matchedConditions));
        } else if (item instanceof ConditionNOT) {
            if (children.isEmpty()) return false;
            return !evaluateCondition(children.getFirst(), event, new ArrayList<>());
        } else {
            return !children.isEmpty()
                    && children.stream()
                            .allMatch(child -> evaluateCondition(child, event, matchedConditions));
        }
    }

    /**
     * Unwraps an {@link AnyOneOf} into a concrete {@link ConditionItem}.
     *
     * <p>The {@code AnyOneOf} may hold a generic {@link ConditionItem}, a {@link
     * ConditionFieldEqualsValueExpression}, or a {@link ConditionValueExpression}.
     *
     * @param anyOneOf the wrapped condition variant
     * @return the unwrapped condition item, or {@code null} if no variant is present
     */
    private ConditionItem resolveConditionItem(
            AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>
                    anyOneOf) {
        if (anyOneOf.isLeft()) return anyOneOf.getLeft();
        if (anyOneOf.isMiddle()) return anyOneOf.getMiddle();
        if (anyOneOf.isRight()) return anyOneOf.get();
        return null;
    }

    /**
     * Checks whether an event field value matches a Sigma detection value.
     *
     * <p>Supported Sigma types:
     *
     * <ul>
     *   <li>{@link SigmaNull} — matches when the event value is {@code null}
     *   <li>{@link SigmaExpansion} — OR over multiple alternatives (windash, base64offset)
     *   <li>{@link SigmaBool} — matches boolean values (including string representations)
     *   <li>{@link SigmaCompareExpression} — numeric comparisons (gt, gte, lt, lte)
     *   <li>{@link SigmaNumber} — exact numeric equality using {@link BigDecimal} for precision
     *   <li>{@link SigmaRegularExpression} — explicit regex matching (re modifier)
     *   <li>{@link SigmaCIDRExpression} — CIDR subnet matching for IP addresses
     *   <li>{@link SigmaString} — case-insensitive string match; supports {@code *} and {@code ?}
     *       wildcards
     * </ul>
     *
     * <p>If the event value is a {@link List}, each element is tested individually.
     *
     * @param eventValue the value from the flattened event (may be {@code null})
     * @param sigmaValue the expected value from the Sigma rule detection
     * @return {@code true} if the event value satisfies the Sigma condition
     */
    private boolean matchValue(Object eventValue, SigmaType sigmaValue) {
        if (sigmaValue instanceof SigmaNull) {
            return eventValue == null;
        }

        // SigmaExpansion
        if (sigmaValue instanceof SigmaExpansion expansion) {
            return expansion.getValues().stream().anyMatch(alt -> matchValue(eventValue, alt));
        }

        if (eventValue instanceof List<?> listValue) {
            return listValue.stream().anyMatch(element -> matchValue(element, sigmaValue));
        }
        if (eventValue == null) {
            return false;
        }

        if (sigmaValue instanceof SigmaBool boolValue) {
            boolean expected = boolValue.isaBoolean();
            return eventValue instanceof Boolean
                    ? expected == (Boolean) eventValue
                    : String.valueOf(expected).equalsIgnoreCase(eventValue.toString());
        }

        // Numeric comparisons
        if (sigmaValue instanceof SigmaCompareExpression compareExpr) {
            try {
                BigDecimal eventDec = new BigDecimal(eventValue.toString());
                BigDecimal sigmaDec = extractBigDecimal(compareExpr.getNumber());
                if (sigmaDec == null) return false;

                int cmp = eventDec.compareTo(sigmaDec);
                return switch (compareExpr.getOp()) {
                    case SigmaCompareExpression.CompareOperators.LT -> cmp < 0;
                    case SigmaCompareExpression.CompareOperators.LTE -> cmp <= 0;
                    case SigmaCompareExpression.CompareOperators.GT -> cmp > 0;
                    case SigmaCompareExpression.CompareOperators.GTE -> cmp >= 0;
                    default -> false;
                };
            } catch (NumberFormatException | NoSuchElementException e) {
                return false;
            }
        }

        // Exact numeric equality
        if (sigmaValue instanceof SigmaNumber numberValue) {
            try {
                BigDecimal eventDec = new BigDecimal(eventValue.toString());
                BigDecimal sigmaDec = extractBigDecimal(numberValue);
                return sigmaDec != null && eventDec.compareTo(sigmaDec) == 0;
            } catch (NumberFormatException | NoSuchElementException e) {
                return false;
            }
        }

        // Explicit regular expression
        if (sigmaValue instanceof SigmaRegularExpression regexValue) {
            try {
                Pattern pattern =
                        regexCache.computeIfAbsent(
                                "re:" + regexValue.getRegexp(), k -> Pattern.compile(regexValue.getRegexp()));
                return pattern.matcher(eventValue.toString()).find();
            } catch (Exception e) {
                log.warn("Failed to evaluate SigmaRegularExpression: {}", regexValue.getRegexp(), e);
                return false;
            }
        }

        // CIDR network matching
        if (sigmaValue instanceof SigmaCIDRExpression cidrExpr) {
            return matchCidr(eventValue.toString(), cidrExpr.getCidr());
        }

        // String matching with optional wildcards
        if (sigmaValue instanceof SigmaString stringValue) {
            if (!stringValue.containsWildcard()) {
                return eventValue.toString().equalsIgnoreCase(stringValue.getOriginal());
            }

            try {
                String cacheKey = stringValue.getOriginal();
                Pattern pattern =
                        regexCache.computeIfAbsent(
                                cacheKey,
                                k -> {
                                    String regex =
                                            "(?i)"
                                                    + stringValue.getsOpt().stream()
                                                            .map(
                                                                    part ->
                                                                            part.isLeft()
                                                                                    ? Pattern.quote(part.getLeft())
                                                                                    : part.getMiddle()
                                                                                                    == SigmaString.SpecialChars.WILDCARD_MULTI
                                                                                            ? ".*"
                                                                                            : ".")
                                                            .collect(Collectors.joining());
                                    return Pattern.compile(regex);
                                });
                return pattern.matcher(eventValue.toString()).matches();
            } catch (Exception e) {
                log.warn(
                        "Failed to evaluate regex pattern for Sigma wildcard: {}",
                        stringValue.getOriginal(),
                        e);
                return false;
            }
        }

        return eventValue.toString().equalsIgnoreCase(sigmaValue.toString());
    }

    /**
     * Formats a Sigma value for human-readable matched condition descriptions.
     *
     * @param value the Sigma type value
     * @return a readable string representation
     */
    private String formatSigmaValue(SigmaType value) {
        if (value instanceof SigmaCompareExpression cmp) {
            return cmp.getOp() + " " + cmp.getNumber();
        }
        if (value instanceof SigmaCIDRExpression cidr) {
            return "cidr:" + cidr.getCidr();
        }
        if (value instanceof SigmaRegularExpression re) {
            return "re:" + re.getRegexp();
        }
        if (value instanceof SigmaExpansion exp) {
            return "expansion(" + exp.getValues().size() + " alternatives)";
        }
        return value.toString();
    }

    /**
     * Extracts a {@link BigDecimal} from a {@link SigmaNumber}'s internal Either representation.
     *
     * @param num the Sigma number value
     * @return the numeric value as BigDecimal, or {@code null} if extraction fails
     */
    private BigDecimal extractBigDecimal(SigmaNumber num) {
        String str;
        if (num.getNumOpt().isLeft()) {
            str = num.getNumOpt().getLeft().toString();
        } else if (num.getNumOpt().isRight()) {
            str = num.getNumOpt().get().toString();
        } else {
            return null;
        }
        return new BigDecimal(str);
    }

    /**
     * Checks if an IP address falls within a CIDR subnet using bitwise comparison.
     *
     * <p>Supports both IPv4 and IPv6 addresses. Thread-safe with no shared mutable state.
     *
     * @param ipStr the event IP address as a string
     * @param cidrStr the CIDR notation subnet (e.g. "192.168.1.0/24" or "2001:db8::/32")
     * @return {@code true} if the IP is within the subnet
     */
    private boolean matchCidr(String ipStr, String cidrStr) {
        try {
            String[] parts = cidrStr.split("/");
            if (parts.length != 2) return false;

            byte[] subnetBytes = InetAddress.getByName(parts[0]).getAddress();
            int prefixLen = Integer.parseInt(parts[1]);
            byte[] ipBytes = InetAddress.getByName(ipStr.trim()).getAddress();

            // IPv4 vs IPv6 length mismatch
            if (ipBytes.length != subnetBytes.length) return false;

            int fullBytes = prefixLen / 8;
            int remainingBits = prefixLen % 8;

            for (int i = 0; i < fullBytes; i++) {
                if (ipBytes[i] != subnetBytes[i]) return false;
            }
            if (remainingBits > 0 && fullBytes < ipBytes.length) {
                int mask = 0xFF << (8 - remainingBits);
                if ((ipBytes[fullBytes] & mask) != (subnetBytes[fullBytes] & mask)) return false;
            }
            return true;
        } catch (UnknownHostException | NumberFormatException | ArrayIndexOutOfBoundsException e) {
            log.warn("Failed CIDR match for IP '{}' against '{}'", ipStr, cidrStr, e);
            return false;
        }
    }
}
