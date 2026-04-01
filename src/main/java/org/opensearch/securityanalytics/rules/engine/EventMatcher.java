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
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/** Evaluates Sigma rules against normalized events. */
public class EventMatcher {

    private static final Logger log = LogManager.getLogger(EventMatcher.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Map<String, Pattern> REGEX_CACHE = new ConcurrentHashMap<>();

    private static final String STATUS_SUCCESS = "success";
    private static final String STATUS_ERROR = "error";
    private static final String UNKNOWN_VALUE = "unknown";

    public EventMatcher() {}

    /**
     * Evaluates a list of pre-parsed Sigma rules against a single event.
     *
     * @param eventJson the event as a JSON string
     * @param rules list of pre-parsed Sigma rules
     * @return a JSON string with evaluation results including matched rules, severity, and tags
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

    private Map<String, Object> buildMatchEntry(SigmaRule rule, List<String> matchedConditions) {
        Map<String, Object> match = new LinkedHashMap<>();
        match.put("rule_id", rule.getId() != null ? rule.getId().toString() : UNKNOWN_VALUE);
        match.put("rule_name", rule.getTitle() != null ? rule.getTitle() : UNKNOWN_VALUE);
        match.put("severity", rule.getLevel() != null ? rule.getLevel().toString() : UNKNOWN_VALUE);
        match.put("matched_conditions", matchedConditions);
        match.put(
                "tags",
                rule.getTags() == null
                        ? Collections.emptyList()
                        : rule.getTags().stream()
                                .map(tag -> tag.getNamespace() + "." + tag.getName())
                                .collect(Collectors.toList()));
        return match;
    }

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

    private boolean evaluateCondition(
            ConditionItem item, Map<String, Object> event, List<String> matchedConditions) {

        if (item instanceof ConditionFieldEqualsValueExpression fieldExpr) {
            if (matchValue(event.get(fieldExpr.getField()), fieldExpr.getValue())) {
                matchedConditions.add(fieldExpr.getField() + " == '" + fieldExpr.getValue() + "'");
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

    private ConditionItem resolveConditionItem(
            AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>
                    anyOneOf) {
        if (anyOneOf.isLeft()) return anyOneOf.getLeft();
        if (anyOneOf.isMiddle()) return anyOneOf.getMiddle();
        if (anyOneOf.isRight()) return anyOneOf.get();
        return null;
    }

    private boolean matchValue(Object eventValue, SigmaType sigmaValue) {
        if (sigmaValue instanceof SigmaNull) {
            return eventValue == null;
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

        if (sigmaValue instanceof SigmaNumber numberValue) {
            try {
                String sigmaNumStr;
                if (numberValue.getNumOpt().isLeft()) {
                    sigmaNumStr = numberValue.getNumOpt().getLeft().toString();
                } else if (numberValue.getNumOpt().isRight()) {
                    sigmaNumStr = numberValue.getNumOpt().get().toString();
                } else {
                    return false;
                }

                BigDecimal eventDec = new BigDecimal(eventValue.toString());
                BigDecimal sigmaDec = new BigDecimal(sigmaNumStr);

                return eventDec.compareTo(sigmaDec) == 0;
            } catch (NumberFormatException | NoSuchElementException e) {
                return false;
            }
        }

        if (sigmaValue instanceof SigmaString stringValue) {
            if (!stringValue.containsWildcard()) {
                return eventValue.toString().equalsIgnoreCase(stringValue.getOriginal());
            }

            try {
                String cacheKey = stringValue.getOriginal();
                Pattern pattern =
                        REGEX_CACHE.computeIfAbsent(
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
}
