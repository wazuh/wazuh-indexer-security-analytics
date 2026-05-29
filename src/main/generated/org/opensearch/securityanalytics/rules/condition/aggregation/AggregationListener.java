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
package org.opensearch.securityanalytics.rules.condition.aggregation;

import org.antlr.v4.runtime.tree.ParseTreeListener;

/**
 * This interface defines a complete listener for a parse tree produced by {@link
 * AggregationParser}.
 */
public interface AggregationListener extends ParseTreeListener {
    /**
     * Enter a parse tree produced by the {@code ComparisonExpressionWithOperator} labeled alternative
     * in {@link AggregationParser#comparison_expr}.
     *
     * @param ctx the parse tree
     */
    void enterComparisonExpressionWithOperator(
            AggregationParser.ComparisonExpressionWithOperatorContext ctx);

    /**
     * Exit a parse tree produced by the {@code ComparisonExpressionWithOperator} labeled alternative
     * in {@link AggregationParser#comparison_expr}.
     *
     * @param ctx the parse tree
     */
    void exitComparisonExpressionWithOperator(
            AggregationParser.ComparisonExpressionWithOperatorContext ctx);

    /**
     * Enter a parse tree produced by {@link AggregationParser#comparison_operand}.
     *
     * @param ctx the parse tree
     */
    void enterComparison_operand(AggregationParser.Comparison_operandContext ctx);

    /**
     * Exit a parse tree produced by {@link AggregationParser#comparison_operand}.
     *
     * @param ctx the parse tree
     */
    void exitComparison_operand(AggregationParser.Comparison_operandContext ctx);

    /**
     * Enter a parse tree produced by {@link AggregationParser#comp_operator}.
     *
     * @param ctx the parse tree
     */
    void enterComp_operator(AggregationParser.Comp_operatorContext ctx);

    /**
     * Exit a parse tree produced by {@link AggregationParser#comp_operator}.
     *
     * @param ctx the parse tree
     */
    void exitComp_operator(AggregationParser.Comp_operatorContext ctx);

    /**
     * Enter a parse tree produced by {@link AggregationParser#agg_operator}.
     *
     * @param ctx the parse tree
     */
    void enterAgg_operator(AggregationParser.Agg_operatorContext ctx);

    /**
     * Exit a parse tree produced by {@link AggregationParser#agg_operator}.
     *
     * @param ctx the parse tree
     */
    void exitAgg_operator(AggregationParser.Agg_operatorContext ctx);

    /**
     * Enter a parse tree produced by {@link AggregationParser#groupby_expr}.
     *
     * @param ctx the parse tree
     */
    void enterGroupby_expr(AggregationParser.Groupby_exprContext ctx);

    /**
     * Exit a parse tree produced by {@link AggregationParser#groupby_expr}.
     *
     * @param ctx the parse tree
     */
    void exitGroupby_expr(AggregationParser.Groupby_exprContext ctx);

    /**
     * Enter a parse tree produced by the {@code AggExpressionParens} labeled alternative in {@link
     * AggregationParser#agg_expr}.
     *
     * @param ctx the parse tree
     */
    void enterAggExpressionParens(AggregationParser.AggExpressionParensContext ctx);

    /**
     * Exit a parse tree produced by the {@code AggExpressionParens} labeled alternative in {@link
     * AggregationParser#agg_expr}.
     *
     * @param ctx the parse tree
     */
    void exitAggExpressionParens(AggregationParser.AggExpressionParensContext ctx);

    /**
     * Enter a parse tree produced by the {@code AggExpressionNumericEntity} labeled alternative in
     * {@link AggregationParser#agg_expr}.
     *
     * @param ctx the parse tree
     */
    void enterAggExpressionNumericEntity(AggregationParser.AggExpressionNumericEntityContext ctx);

    /**
     * Exit a parse tree produced by the {@code AggExpressionNumericEntity} labeled alternative in
     * {@link AggregationParser#agg_expr}.
     *
     * @param ctx the parse tree
     */
    void exitAggExpressionNumericEntity(AggregationParser.AggExpressionNumericEntityContext ctx);

    /**
     * Enter a parse tree produced by the {@code NumericConst} labeled alternative in {@link
     * AggregationParser#numeric_entity}.
     *
     * @param ctx the parse tree
     */
    void enterNumericConst(AggregationParser.NumericConstContext ctx);

    /**
     * Exit a parse tree produced by the {@code NumericConst} labeled alternative in {@link
     * AggregationParser#numeric_entity}.
     *
     * @param ctx the parse tree
     */
    void exitNumericConst(AggregationParser.NumericConstContext ctx);

    /**
     * Enter a parse tree produced by the {@code NumericVariable} labeled alternative in {@link
     * AggregationParser#numeric_entity}.
     *
     * @param ctx the parse tree
     */
    void enterNumericVariable(AggregationParser.NumericVariableContext ctx);

    /**
     * Exit a parse tree produced by the {@code NumericVariable} labeled alternative in {@link
     * AggregationParser#numeric_entity}.
     *
     * @param ctx the parse tree
     */
    void exitNumericVariable(AggregationParser.NumericVariableContext ctx);
}
