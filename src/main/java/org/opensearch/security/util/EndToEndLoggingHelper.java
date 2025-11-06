package org.opensearch.security.util;

import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.ClusterSettings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.security.support.SecuritySettings;

import static org.opensearch.security.support.ConfigConstants.TOOKTIME_LOG_THRESHOLD_DEFAULT;

public class EndToEndLoggingHelper {
    private static TimeValue loggingThreshold = TOOKTIME_LOG_THRESHOLD_DEFAULT;

    public static void registerClusterSettingsChangeListener(final ClusterSettings clusterSettings) {
        clusterSettings.addSettingsUpdateConsumer(
            SecuritySettings.TOOKTIME_LOG_THRESHOLD_SETTING,
            EndToEndLoggingHelper::updateTooktimeLogThreshold
        );
    }

    private static void updateTooktimeLogThreshold(TimeValue newThreshold) {
        loggingThreshold = newThreshold;
    }

    public static long getLoggingThresholdNanos() {
        return loggingThreshold.getNanos();
    }

    public static void maybeLogEndToEnd(String traceparent, long startTime, String baseLogString, Logger log) {
        long elapsed = System.nanoTime() - startTime;
        if (elapsed < getLoggingThresholdNanos()) return;
        if (traceparent != null && !traceparent.isEmpty()) {
            log.info(baseLogString + " with traceparent header = " + traceparent + " in " + elapsed + "ns");
        } else {
            log.info(baseLogString + " with no traceparent header in " + elapsed + "ns");
        }
    }
}
