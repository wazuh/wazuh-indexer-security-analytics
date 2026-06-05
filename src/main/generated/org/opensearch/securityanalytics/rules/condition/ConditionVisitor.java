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

import org.antlr.v4.runtime.tree.ParseTreeVisitor;

/**
 * This interface defines a complete generic visitor for a parse tree produced by {@link
 * ConditionParser}.
 *
 * @param <T> The return type of the visit operation. Use {@link Void} for operations with no return
 *     type.
 */
public interface ConditionVisitor<T> extends ParseTreeVisitor<T> {
    /**
     * Visit a parse tree produced by {@link ConditionParser#start}.
     *
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitStart(ConditionParser.StartContext ctx);

    /**
     * Visit a parse tree produced by the {@code orExpression} labeled alternative in {@link
     * ConditionParser#expression}.
     *
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitOrExpression(ConditionParser.OrExpressionContext ctx);

    /**
     * Visit a parse tree produced by the {@code identOrSelectExpression} labeled alternative in
     * {@link ConditionParser#expression}.
     *
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitIdentOrSelectExpression(ConditionParser.IdentOrSelectExpressionContext ctx);

    /**
     * Visit a parse tree produced by the {@code andExpression} labeled alternative in {@link
     * ConditionParser#expression}.
     *
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitAndExpression(ConditionParser.AndExpressionContext ctx);

    /**
     * Visit a parse tree produced by the {@code notExpression} labeled alternative in {@link
     * ConditionParser#expression}.
     *
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitNotExpression(ConditionParser.NotExpressionContext ctx);

    /**
     * Visit a parse tree produced by the {@code parenExpression} labeled alternative in {@link
     * ConditionParser#expression}.
     *
     * @param ctx the parse tree
     * @return the visitor result
     */
    T visitParenExpression(ConditionParser.ParenExpressionContext ctx);
}
