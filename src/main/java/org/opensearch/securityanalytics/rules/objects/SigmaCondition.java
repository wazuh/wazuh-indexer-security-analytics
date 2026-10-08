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
package org.opensearch.securityanalytics.rules.objects;

import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;

import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.securityanalytics.rules.aggregation.AggregationItem;
import org.opensearch.securityanalytics.rules.aggregation.AggregationTraverseVisitor;
import org.opensearch.securityanalytics.rules.condition.ConditionFieldEqualsValueExpression;
import org.opensearch.securityanalytics.rules.condition.ConditionIdentifier;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.condition.ConditionLexer;
import org.opensearch.securityanalytics.rules.condition.ConditionParser;
import org.opensearch.securityanalytics.rules.condition.ConditionSelector;
import org.opensearch.securityanalytics.rules.condition.ConditionTraverseVisitor;
import org.opensearch.securityanalytics.rules.condition.ConditionValueExpression;
import org.opensearch.securityanalytics.rules.condition.aggregation.AggregationLexer;
import org.opensearch.securityanalytics.rules.condition.aggregation.AggregationParser;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SigmaCondition {

    /**
     * Longest condition accepted, in characters. The longest condition among the Sigma rules this
     * plugin bundles is 542 characters.
     */
    public static final int MAX_CONDITION_LENGTH = 4096;

    /**
     * Deepest parenthesis nesting accepted. ANTLR parses each level by recursion. The bundled Sigma
     * rules nest at most 2 levels.
     */
    public static final int MAX_CONDITION_NESTING = 32;

    /**
     * Most logical operators ({@code and}, {@code or}, {@code not}) accepted in one condition. The
     * parse tree is binary, so a chain of N operators is N levels deep, and the visitor and the query
     * backend recurse once per level: a chain a few hundred operators long overflows a 1 MiB thread
     * stack. The bundled Sigma rules use at most 35.
     */
    public static final int MAX_CONDITION_OPERATORS = 128;

    private final String identifier = "[a-zA-Z0-9-_]+";

    private final List<String> quantifier = List.of("1", "any", "all");

    private final String identifierPattern = "[a-zA-Z0-9*_]+";

    private final List<Either<List<String>, String>> selector =
            List.of(Either.left(quantifier), Either.right("of"), Either.right(identifierPattern));

    private static final Pattern OPERATOR_PATTERN =
            Pattern.compile("\\b(and|or|not)\\b", Pattern.CASE_INSENSITIVE);

    private final List<String> operators = List.of("not ", " and ", " or ");

    private String condition;

    private String aggregation;

    private SigmaDetections detections;

    private ConditionParser parser;

    private AggregationParser aggParser;

    private ConditionTraverseVisitor conditionVisitor;

    private AggregationTraverseVisitor aggVisitor;

    /**
     * Normalize operators in the condition string to lowercase to ensure they are correctly
     * recognized by the ANTLR lexer, which defines them as lowercase literals. This allows users to
     * write conditions using uppercase operators (e.g., "AND", "OR", "NOT") without causing parsing
     * errors, while still preserving the case of detection identifiers.
     *
     * @param condition the condition string to normalize
     * @return the normalized condition string with operators in lowercase
     */
    private static String normalizeOperators(String condition) {
        Matcher m = OPERATOR_PATTERN.matcher(condition);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            m.appendReplacement(sb, m.group().toLowerCase());
        }
        m.appendTail(sb);
        return sb.toString();
    }

    /**
     * Rejects a condition too large to parse and convert safely. Every stage after this one (the
     * ANTLR parser, the condition visitor, the query backend) recurses once per nesting level and per
     * operator, and a {@link StackOverflowError} escaping them takes the node down. The checks are a
     * single linear pass, so they cost nothing for a condition of legitimate size.
     *
     * @param condition the condition as written in the rule, aggregation included.
     * @throws SigmaConditionError when the condition exceeds one of the limits.
     */
    static void validateSize(String condition) throws SigmaConditionError {
        if (condition.length() > MAX_CONDITION_LENGTH) {
            throw new SigmaConditionError(
                    String.format(
                            Locale.ROOT,
                            "Sigma condition is %d characters long, more than the %d allowed",
                            condition.length(),
                            MAX_CONDITION_LENGTH));
        }
        int depth = 0;
        for (int i = 0; i < condition.length(); i++) {
            char c = condition.charAt(i);
            if (c == '(' && ++depth > MAX_CONDITION_NESTING) {
                throw new SigmaConditionError(
                        String.format(
                                Locale.ROOT,
                                "Sigma condition nests parentheses more than %d levels deep",
                                MAX_CONDITION_NESTING));
            } else if (c == ')' && depth > 0) {
                depth--;
            }
        }
        int operators = 0;
        Matcher m = OPERATOR_PATTERN.matcher(condition);
        while (m.find()) {
            operators++;
        }
        if (operators > MAX_CONDITION_OPERATORS) {
            throw new SigmaConditionError(
                    String.format(
                            Locale.ROOT,
                            "Sigma condition has %d logical operators, more than the %d allowed",
                            operators,
                            MAX_CONDITION_OPERATORS));
        }
    }

    public SigmaCondition(String condition, SigmaDetections detections) throws SigmaConditionError {
        SigmaCondition.validateSize(condition);
        condition = SigmaCondition.normalizeOperators(condition);
        if (condition.contains(" | ")) {
            this.condition = condition.split(" \\| ")[0];
            this.aggregation = condition.split(" \\| ")[1];
        } else {
            this.condition = condition;
            this.aggregation = "";
        }

        this.detections = detections;

        ConditionLexer lexer = new ConditionLexer(CharStreams.fromString(this.condition));
        this.parser = new ConditionParser(new CommonTokenStream(lexer));
        this.conditionVisitor = new ConditionTraverseVisitor(this);

        AggregationLexer aggLexer = new AggregationLexer(CharStreams.fromString(this.aggregation));
        this.aggParser = new AggregationParser(new CommonTokenStream(aggLexer));
        this.aggVisitor = new AggregationTraverseVisitor();
    }

    /**
     * Parses the condition and its aggregation.
     *
     * <p>{@link #validateSize} keeps conditions shallow enough to parse, so a {@link
     * StackOverflowError} here is not expected. Should one happen anyway, it is reported as a
     * condition error: the parse works only on this object's own state, so nothing is left
     * half-updated, and letting the error escape would reach OpenSearch's uncaught-error handler,
     * which halts the node.
     *
     * @return the parsed condition and, when the condition has one, its aggregation.
     * @throws SigmaConditionError when the condition cannot be parsed.
     */
    public Pair<ConditionItem, AggregationItem> parsed() throws SigmaConditionError {
        try {
            return this.parse();
        } catch (StackOverflowError e) {
            throw new SigmaConditionError("Sigma condition is too deeply nested to parse");
        }
    }

    private Pair<ConditionItem, AggregationItem> parse() throws SigmaConditionError {
        ConditionItem parsedConditionItem;
        Either<ConditionItem, String> itemOrCondition = conditionVisitor.visit(parser.start());
        if (itemOrCondition.isLeft()) {
            parsedConditionItem = itemOrCondition.getLeft();
        } else {
            parsedConditionItem =
                    Objects.requireNonNull(parsed(condition)).isLeft()
                            ? Objects.requireNonNull(parsed(condition)).getLeft()
                            : ((Objects.requireNonNull(parsed(condition))).isMiddle()
                                    ? Objects.requireNonNull(parsed(condition)).getMiddle()
                                    : Objects.requireNonNull(parsed(condition)).get());
        }

        AggregationItem parsedAggItem = null;
        if (!this.aggregation.isEmpty()) {
            aggVisitor.visit(aggParser.comparison_expr());
            parsedAggItem = aggVisitor.getAggregationItem();
        }
        return Pair.of(parsedConditionItem, parsedAggItem);
    }

    public List<
                    Either<
                            AnyOneOf<
                                    ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>,
                            String>>
            convertArgs(
                    List<
                                    Either<
                                            AnyOneOf<
                                                    ConditionItem,
                                                    ConditionFieldEqualsValueExpression,
                                                    ConditionValueExpression>,
                                            String>>
                            parsedArgs)
                    throws SigmaConditionError {
        List<
                        Either<
                                AnyOneOf<
                                        ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>,
                                String>>
                newArgs = new ArrayList<>();

        for (Either<
                        AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>,
                        String>
                parsedArg : parsedArgs) {
            if (parsedArg.isRight()) {
                AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>
                        newItem = parsed(parsedArg.get());
                newArgs.add(Either.left(newItem));
            } else {
                newArgs.add(parsedArg);
            }
        }
        return newArgs;
    }

    private AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>
            parsed(String token) throws SigmaConditionError {
        List<String> subTokens = List.of(token.split(" "));
        if (subTokens.size() < 3 && token.matches(identifier)) {
            ConditionIdentifier conditionIdentifier =
                    new ConditionIdentifier(Collections.singletonList(Either.right(token)));
            ConditionItem item = conditionIdentifier.postProcess(detections, null);
            return item instanceof ConditionFieldEqualsValueExpression
                    ? AnyOneOf.middleVal((ConditionFieldEqualsValueExpression) item)
                    : (item instanceof ConditionValueExpression
                            ? AnyOneOf.rightVal((ConditionValueExpression) item)
                            : AnyOneOf.leftVal(item));
        } else if (subTokens.size() == 3
                && quantifier.contains(subTokens.get(0))
                && selector.get(1).get().equals(subTokens.get(1))
                && subTokens.get(2).matches(identifierPattern)) {
            ConditionSelector conditionSelector =
                    new ConditionSelector(subTokens.get(0), subTokens.get(2));
            ConditionItem item = conditionSelector.postProcess(detections, null);
            return item instanceof ConditionFieldEqualsValueExpression
                    ? AnyOneOf.middleVal((ConditionFieldEqualsValueExpression) item)
                    : (item instanceof ConditionValueExpression
                            ? AnyOneOf.rightVal((ConditionValueExpression) item)
                            : AnyOneOf.leftVal(item));
        }
        return null;
    }
}
