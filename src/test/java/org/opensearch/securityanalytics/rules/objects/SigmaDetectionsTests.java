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

import org.opensearch.securityanalytics.rules.condition.ConditionAND;
import org.opensearch.securityanalytics.rules.condition.ConditionFieldEqualsValueExpression;
import org.opensearch.securityanalytics.rules.condition.ConditionItem;
import org.opensearch.securityanalytics.rules.condition.ConditionOR;
import org.opensearch.securityanalytics.rules.condition.ConditionValueExpression;
import org.opensearch.securityanalytics.rules.exceptions.SigmaConditionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaDetectionError;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.modifiers.SigmaContainsModifier;
import org.opensearch.securityanalytics.rules.modifiers.SigmaEndswithModifier;
import org.opensearch.securityanalytics.rules.types.SigmaNumber;
import org.opensearch.securityanalytics.rules.types.SigmaString;
import org.opensearch.securityanalytics.rules.utils.AnyOneOf;
import org.opensearch.securityanalytics.rules.utils.Either;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

public class SigmaDetectionsTests extends OpenSearchTestCase {

    public void testSigmaDetectionsFromDict() throws SigmaError {
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        Map<String, Object> detectionsMap =
                yaml.load(
                        "    selection:\n"
                                + "        EventID: 16\n"
                                + "        HiveName|contains: '\\AppData\\Local\\Temp\\SAM'\n"
                                + "        HiveName|endswith: '.dmp'\n"
                                + "    condition: selection");

        SigmaDetections actualSigmaDetections = SigmaDetections.fromDict(detectionsMap);

        SigmaDetectionItem detectionItem1 =
                new SigmaDetectionItem(
                        "EventID", Collections.emptyList(), List.of(new SigmaNumber(16)), null, null, false);
        SigmaDetectionItem detectionItem2 =
                new SigmaDetectionItem(
                        "HiveName",
                        Collections.singletonList(SigmaContainsModifier.class),
                        List.of(new SigmaString("\\AppData\\Local\\Temp\\SAM")),
                        null,
                        null,
                        false);
        SigmaDetectionItem detectionItem4 =
                new SigmaDetectionItem(
                        "HiveName",
                        Collections.singletonList(SigmaEndswithModifier.class),
                        List.of(new SigmaString(".dmp")),
                        null,
                        null,
                        false);

        SigmaDetection detection =
                new SigmaDetection(
                        List.of(
                                Either.left(detectionItem1),
                                Either.left(detectionItem2),
                                Either.left(detectionItem4)),
                        Either.right(ConditionOR.class));
        SigmaDetections expectedSigmaDetections =
                new SigmaDetections(
                        Collections.singletonMap("selection", detection),
                        Collections.singletonList("selection"),
                        null);

        Assert.assertEquals(
                expectedSigmaDetections.getCondition().size(), actualSigmaDetections.getCondition().size());
        Assert.assertEquals(
                expectedSigmaDetections.getCondition().get(0), actualSigmaDetections.getCondition().get(0));

        Assert.assertEquals(
                expectedSigmaDetections.getDetections().get("selection").getDetectionItems().size(),
                actualSigmaDetections.getDetections().get("selection").getDetectionItems().size());

        Assert.assertTrue(
                actualSigmaDetections.getParsedCondition().size() > 0
                        && actualSigmaDetections.getParsedCondition().get(0) != null);
    }

    public void testSigmaDetectionsFromDictTimeframeIsNotADetection() throws SigmaError {
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        Map<String, Object> detectionsMap =
                yaml.load(
                        "    timeframe: 5m\n"
                                + "    selection1:\n"
                                + "        EventID: 16\n"
                                + "    selection2:\n"
                                + "        EventID: 17\n"
                                + "    condition: 1 of them");

        SigmaDetections sigmaDetections = SigmaDetections.fromDict(detectionsMap);

        Assert.assertEquals("5m", sigmaDetections.getTimeframe());
        Assert.assertEquals(
                Set.of("selection1", "selection2"), sigmaDetections.getDetections().keySet());

        ConditionItem conditionItem = sigmaDetections.getParsedCondition().get(0).parsed().getLeft();
        Assert.assertTrue(conditionItem instanceof ConditionOR);
        Assert.assertEquals(2, conditionItem.getArgs().size());
    }

    public void testSigmaDetectionsFromDictNoDetections() {
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        Map<String, Object> detectionsMap = yaml.load("    condition: selection");
        Exception exception =
                assertThrows(
                        SigmaDetectionError.class,
                        () -> {
                            SigmaDetections.fromDict(detectionsMap);
                        });

        String expectedMessage = "No detections defined in Sigma rule";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testSigmaDetectionsFromDictNoCondition() {
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        Map<String, Object> detectionsMap =
                yaml.load(
                        "    selection:\n"
                                + "        EventID: 16\n"
                                + "        HiveName|contains: '\\AppData\\Local\\Temp\\SAM'\n"
                                + "        HiveName|endswith: '.dmp'");

        Exception exception =
                assertThrows(
                        SigmaConditionError.class,
                        () -> {
                            SigmaDetections.fromDict(detectionsMap);
                        });

        String expectedMessage = "Sigma rule must contain at least one condition";
        String actualMessage = exception.getMessage();

        assertTrue(actualMessage.contains(expectedMessage));
    }

    public void testDetectionItemAllModifiedKeyPlainValuesPostProcess() throws SigmaError {
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        Map<String, Object> detectionsMap =
                yaml.load(
                        "    selection:\n"
                                + "        field|all: [\"val1\", \"val2\", 123]\n"
                                + "    condition: selection");
        SigmaDetections sigmaDetections = SigmaDetections.fromDict(detectionsMap);

        ConditionItem conditionItem = sigmaDetections.getParsedCondition().get(0).parsed().getLeft();
        Assert.assertTrue(conditionItem instanceof ConditionAND);

        for (Either<
                        AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>,
                        String>
                arg : conditionItem.getArgs()) {
            Assert.assertTrue(arg.isLeft() && arg.getLeft().isMiddle());
            Assert.assertTrue(
                    arg.getLeft().getMiddle().getValue() instanceof SigmaString
                            || arg.getLeft().getMiddle().getValue() instanceof SigmaNumber);
        }
    }

    public void testDetectionItemAllModifiedUnboundPlainValuesPostProcess() throws SigmaError {
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        Map<String, Object> detectionsMap =
                yaml.load(
                        "    selection:\n"
                                + "        \"|all\": [\"val1\", \"val2\", 123]\n"
                                + "    condition: selection");
        SigmaDetections sigmaDetections = SigmaDetections.fromDict(detectionsMap);

        ConditionItem conditionItem = sigmaDetections.getParsedCondition().get(0).parsed().getLeft();
        Assert.assertTrue(conditionItem instanceof ConditionAND);

        for (Either<
                        AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>,
                        String>
                arg : conditionItem.getArgs()) {
            Assert.assertTrue(arg.isLeft() && arg.getLeft().isRight());
            Assert.assertTrue(
                    arg.getLeft().get().getValue() instanceof SigmaString
                            || arg.getLeft().get().getValue() instanceof SigmaNumber);
        }
    }

    public void testDetectionItemAllModifiedKeySpecialValuesPostProcess() throws SigmaError {
        Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
        Map<String, Object> detectionsMap =
                yaml.load(
                        "    selection:\n"
                                + "        field|all: [\"val1*\", \"val2\", 123]\n"
                                + "    condition: selection");
        SigmaDetections sigmaDetections = SigmaDetections.fromDict(detectionsMap);

        ConditionItem conditionItem = sigmaDetections.getParsedCondition().get(0).parsed().getLeft();
        Assert.assertTrue(conditionItem instanceof ConditionAND);

        for (Either<
                        AnyOneOf<ConditionItem, ConditionFieldEqualsValueExpression, ConditionValueExpression>,
                        String>
                arg : conditionItem.getArgs()) {
            Assert.assertTrue(arg.isLeft() && arg.getLeft().isMiddle());
            Assert.assertTrue(
                    (arg.getLeft().getMiddle().getValue() instanceof SigmaString
                                    && (((SigmaString) arg.getLeft().getMiddle().getValue())
                                                    .getOriginal()
                                                    .equals("val1*")
                                            || ((SigmaString) arg.getLeft().getMiddle().getValue())
                                                    .getOriginal()
                                                    .equals("val2")))
                            || arg.getLeft().getMiddle().getValue() instanceof SigmaNumber);
        }
    }
}
