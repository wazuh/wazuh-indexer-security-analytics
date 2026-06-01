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

import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.tree.ErrorNode;
import org.antlr.v4.runtime.tree.TerminalNode;

/**
 * This class provides an empty implementation of {@link AggregationListener}, which can be extended
 * to create a listener which only needs to handle a subset of the available methods.
 */
@SuppressWarnings("CheckReturnValue")
public class AggregationBaseListener implements AggregationListener {
    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterComparisonExpressionWithOperator(
            AggregationParser.ComparisonExpressionWithOperatorContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitComparisonExpressionWithOperator(
            AggregationParser.ComparisonExpressionWithOperatorContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterComparison_operand(AggregationParser.Comparison_operandContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitComparison_operand(AggregationParser.Comparison_operandContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterComp_operator(AggregationParser.Comp_operatorContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitComp_operator(AggregationParser.Comp_operatorContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterAgg_operator(AggregationParser.Agg_operatorContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitAgg_operator(AggregationParser.Agg_operatorContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterGroupby_expr(AggregationParser.Groupby_exprContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitGroupby_expr(AggregationParser.Groupby_exprContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterAggExpressionParens(AggregationParser.AggExpressionParensContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitAggExpressionParens(AggregationParser.AggExpressionParensContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterAggExpressionNumericEntity(
            AggregationParser.AggExpressionNumericEntityContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitAggExpressionNumericEntity(
            AggregationParser.AggExpressionNumericEntityContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterNumericConst(AggregationParser.NumericConstContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitNumericConst(AggregationParser.NumericConstContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterNumericVariable(AggregationParser.NumericVariableContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitNumericVariable(AggregationParser.NumericVariableContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterEveryRule(ParserRuleContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitEveryRule(ParserRuleContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void visitTerminal(TerminalNode node) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void visitErrorNode(ErrorNode node) {}
}
