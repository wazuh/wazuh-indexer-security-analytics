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

import org.antlr.v4.runtime.tree.ParseTreeListener;

/**
 * This interface defines a complete listener for a parse tree produced by {@link ConditionParser}.
 */
public interface ConditionListener extends ParseTreeListener {
    /**
     * Enter a parse tree produced by {@link ConditionParser#start}.
     *
     * @param ctx the parse tree
     */
    void enterStart(ConditionParser.StartContext ctx);

    /**
     * Exit a parse tree produced by {@link ConditionParser#start}.
     *
     * @param ctx the parse tree
     */
    void exitStart(ConditionParser.StartContext ctx);

    /**
     * Enter a parse tree produced by the {@code orExpression} labeled alternative in {@link
     * ConditionParser#expression}.
     *
     * @param ctx the parse tree
     */
    void enterOrExpression(ConditionParser.OrExpressionContext ctx);

    /**
     * Exit a parse tree produced by the {@code orExpression} labeled alternative in {@link
     * ConditionParser#expression}.
     *
     * @param ctx the parse tree
     */
    void exitOrExpression(ConditionParser.OrExpressionContext ctx);

    /**
     * Enter a parse tree produced by the {@code identOrSelectExpression} labeled alternative in
     * {@link ConditionParser#expression}.
     *
     * @param ctx the parse tree
     */
    void enterIdentOrSelectExpression(ConditionParser.IdentOrSelectExpressionContext ctx);

    /**
     * Exit a parse tree produced by the {@code identOrSelectExpression} labeled alternative in {@link
     * ConditionParser#expression}.
     *
     * @param ctx the parse tree
     */
    void exitIdentOrSelectExpression(ConditionParser.IdentOrSelectExpressionContext ctx);

    /**
     * Enter a parse tree produced by the {@code andExpression} labeled alternative in {@link
     * ConditionParser#expression}.
     *
     * @param ctx the parse tree
     */
    void enterAndExpression(ConditionParser.AndExpressionContext ctx);

    /**
     * Exit a parse tree produced by the {@code andExpression} labeled alternative in {@link
     * ConditionParser#expression}.
     *
     * @param ctx the parse tree
     */
    void exitAndExpression(ConditionParser.AndExpressionContext ctx);

    /**
     * Enter a parse tree produced by the {@code notExpression} labeled alternative in {@link
     * ConditionParser#expression}.
     *
     * @param ctx the parse tree
     */
    void enterNotExpression(ConditionParser.NotExpressionContext ctx);

    /**
     * Exit a parse tree produced by the {@code notExpression} labeled alternative in {@link
     * ConditionParser#expression}.
     *
     * @param ctx the parse tree
     */
    void exitNotExpression(ConditionParser.NotExpressionContext ctx);

    /**
     * Enter a parse tree produced by the {@code parenExpression} labeled alternative in {@link
     * ConditionParser#expression}.
     *
     * @param ctx the parse tree
     */
    void enterParenExpression(ConditionParser.ParenExpressionContext ctx);

    /**
     * Exit a parse tree produced by the {@code parenExpression} labeled alternative in {@link
     * ConditionParser#expression}.
     *
     * @param ctx the parse tree
     */
    void exitParenExpression(ConditionParser.ParenExpressionContext ctx);
}
