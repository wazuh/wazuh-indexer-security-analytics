/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

import org.opensearch.securityanalytics.rules.exceptions.SigmaRegularExpressionError;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SigmaRegularExpression implements SigmaType {

    /**
     * Longest pattern accepted, in characters: the default of OpenSearch's
     * {@code index.max_regex_length}, which the generated query is held to anyway. The longest
     * pattern among the Sigma rules this plugin bundles is 144 characters.
     */
    public static final int MAX_REGEX_LENGTH = 1000;

    /**
     * Most opening parentheses accepted in one pattern. Lucene parses a group by recursion, and a few
     * hundred nested groups overflow a 1 MiB thread stack, which halts the node. Every {@code (}
     * is counted, escaped or not, because the backend doubles backslashes on the way to Lucene, so
     * an escaped parenthesis in the Sigma pattern can arrive at Lucene as a group. The count is then
     * a bound on the nesting depth however the pattern is read. The bundled Sigma rules use at most
     * 4.
     */
    public static final int MAX_REGEX_PARENTHESES = 32;

    private String regexp;

    public SigmaRegularExpression(String regexp) throws SigmaRegularExpressionError {
        validateSize(regexp);
        this.regexp = regexp.replace(" ", "_ws_");
        this.compile();
    }

    /**
     * Rejects a pattern too large to compile safely, before anything parses it.
     *
     * @param regexp the pattern as written in the rule.
     * @throws SigmaRegularExpressionError when the pattern exceeds one of the limits.
     */
    static void validateSize(String regexp) throws SigmaRegularExpressionError {
        if (regexp.length() > MAX_REGEX_LENGTH) {
            throw new SigmaRegularExpressionError(
                    String.format(
                            Locale.ROOT,
                            "Regular expression is %d characters long, more than the %d allowed",
                            regexp.length(),
                            MAX_REGEX_LENGTH));
        }
        long parentheses = regexp.chars().filter(c -> c == '(').count();
        if (parentheses > MAX_REGEX_PARENTHESES) {
            throw new SigmaRegularExpressionError(
                    String.format(
                            Locale.ROOT,
                            "Regular expression has %d opening parentheses, more than the %d allowed",
                            parentheses,
                            MAX_REGEX_PARENTHESES));
        }
    }

    public void compile() throws SigmaRegularExpressionError {
        try {
            Pattern.compile(this.regexp);
        } catch (Exception ex) {
            throw new SigmaRegularExpressionError("Regular expression '" + this.regexp + "' is invalid: " + ex.getMessage());
        }
    }

    public String escape(List<String> escaped, String escapeChar) {
        if (escapeChar == null || escapeChar.isEmpty()) {
            escapeChar = "\\";
        }

        List<String> rList = new ArrayList<>();
        for (String escape: escaped) {
            rList.add(Pattern.quote(escape));
        }
        rList.add(Pattern.quote(escapeChar));
        String r = String.join("|", rList);

        List<Integer> pos = new ArrayList<>();
        pos.add(0);

        Pattern pattern = Pattern.compile(r);
        Matcher matcher = pattern.matcher(this.regexp);

        while (matcher.find()) {
            pos.add(matcher.start());
        }
        pos.add(this.regexp.length());

        List<String> ranges = new ArrayList<>();
        for (int i = 0; i < pos.size()-1; ++i) {
            ranges.add(this.regexp.substring(pos.get(i), pos.get(i+1)));
        }
        return String.join(escapeChar, ranges);
    }

    public String getRegexp() {
        return regexp;
    }

    public void setRegexp(String regexp) {
        this.regexp = regexp;
    }

    @Override
    public String toString() {
        return this.regexp;
    }
}