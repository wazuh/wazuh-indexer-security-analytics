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
package org.opensearch.securityanalytics.rules.condition;

import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.tree.ErrorNode;
import org.antlr.v4.runtime.tree.TerminalNode;

/**
 * This class provides an empty implementation of {@link ConditionListener}, which can be extended
 * to create a listener which only needs to handle a subset of the available methods.
 */
@SuppressWarnings("CheckReturnValue")
public class ConditionBaseListener implements ConditionListener {
    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterStart(ConditionParser.StartContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitStart(ConditionParser.StartContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterOrExpression(ConditionParser.OrExpressionContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitOrExpression(ConditionParser.OrExpressionContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterIdentOrSelectExpression(ConditionParser.IdentOrSelectExpressionContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitIdentOrSelectExpression(ConditionParser.IdentOrSelectExpressionContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterAndExpression(ConditionParser.AndExpressionContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitAndExpression(ConditionParser.AndExpressionContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterNotExpression(ConditionParser.NotExpressionContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitNotExpression(ConditionParser.NotExpressionContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void enterParenExpression(ConditionParser.ParenExpressionContext ctx) {}

    /**
     * {@inheritDoc}
     *
     * <p>The default implementation does nothing.
     */
    @Override
    public void exitParenExpression(ConditionParser.ParenExpressionContext ctx) {}

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
