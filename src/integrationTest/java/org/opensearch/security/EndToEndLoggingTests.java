package org.opensearch.security;

import java.io.CharArrayWriter;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import com.google.common.collect.ImmutableMap;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.StringLayout;
import org.apache.logging.log4j.core.appender.WriterAppender;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.awaitility.Awaitility;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.opensearch.action.admin.cluster.settings.ClusterUpdateSettingsRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.security.filter.SecurityFilter;
import org.opensearch.security.filter.SecurityRestFilter;
import org.opensearch.security.ssl.http.netty.Netty4HttpRequestHeaderVerifier;
import org.opensearch.security.ssl.transport.SecuritySSLRequestHandler;
import org.opensearch.security.transport.SecurityInterceptor;
import org.opensearch.security.transport.SecurityRequestHandler;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;
import org.opensearch.test.framework.cluster.TestRestClient;
import org.opensearch.transport.client.Client;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.opensearch.security.support.ConfigConstants.SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX;
import static org.opensearch.security.support.ConfigConstants.SECURITY_RESTAPI_ROLES_ENABLED;
import static org.opensearch.security.support.ConfigConstants.TOOKTIME_LOG_THRESHOLD;
import static org.opensearch.security.support.ConfigConstants.TRACEPARENT_HEADER;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.TestSecurityConfig.Role.ALL_ACCESS;
import static org.opensearch.test.framework.matcher.RestMatchers.isOk;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(com.carrotsearch.randomizedtesting.RandomizedRunner.class)
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
public class EndToEndLoggingTests {
    private final static Path configurationFolder = ConfigurationFiles.createConfigurationDirectory();
    private static final TestSecurityConfig.User USER_ADMIN = new TestSecurityConfig.User("admin").roles(ALL_ACCESS);

    private static LocalCluster createCluster(final Map<String, Object> nodeSettings) {
        var cluster = new LocalCluster.Builder().clusterManager(ClusterManager.THREE_CLUSTER_MANAGERS)
            .loadConfigurationIntoIndex(false)
            .defaultConfigurationInitDirectory(configurationFolder.toString())
            .nodeSettings(
                ImmutableMap.<String, Object>builder()
                    .put(SECURITY_RESTAPI_ROLES_ENABLED, List.of("user_" + USER_ADMIN.getName() + "__" + ALL_ACCESS.getName()))
                    .put(SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX, true)
                    .putAll(nodeSettings)
                    .build()
            )
            .authc(AUTHC_HTTPBASIC_INTERNAL)
            .build();

        cluster.before();
        return cluster;
    }

    @Test
    public void testLogging() throws Exception {
        // Setup code so we can inspect log output - see https://www.dontpanicblog.co.uk/2018/04/29/test-log4j2-with-junit/
        Logger e2eLoggerRestFilter = (Logger) LogManager.getLogger(SecurityRestFilter.class);
        Logger e2eLoggerHeaderVerifier = (Logger) LogManager.getLogger(Netty4HttpRequestHeaderVerifier.class);
        Logger e2eLoggerActionFilter = (Logger) LogManager.getLogger(SecurityFilter.class);
        Logger e2eLoggerTransportReceived = (Logger) LogManager.getLogger(SecurityRequestHandler.class);
        Logger e2eLoggerTransportSent = (Logger) LogManager.getLogger(SecurityInterceptor.class);

        Map<Logger, String> loggerStrings = Map.of(
            e2eLoggerRestFilter,
            SecurityRestFilter.END_TO_END_LOGGING_BASE_STRING,
            e2eLoggerHeaderVerifier,
            Netty4HttpRequestHeaderVerifier.END_TO_END_LOGGING_BASE_STRING,
            e2eLoggerActionFilter,
            SecurityFilter.END_TO_END_LOGGING_BASE_STRING,
            e2eLoggerTransportReceived,
            SecuritySSLRequestHandler.END_TO_END_LOGGING_BASE_STRING,
            e2eLoggerTransportSent,
            SecurityInterceptor.END_TO_END_LOGGING_BASE_STRING
        );
        List<Appender> appenders = new ArrayList<>();
        StringLayout layout = PatternLayout.newBuilder().withPattern("%-5level %msg").build();
        Map<Logger, CharArrayWriter> loggerOutputs = new HashMap<>();

        for (Logger logger : loggerStrings.keySet()) {
            CharArrayWriter loggerOutput = new CharArrayWriter();
            Appender appender = WriterAppender.newBuilder().setTarget(loggerOutput).setLayout(layout).setName("appender").build();
            appenders.add(appender);
            appender.start();
            logger.addAppender(appender);
            loggerOutputs.put(logger, loggerOutput);
        }

        try (final LocalCluster cluster = createCluster(new HashMap<>())) {
            List<String> traceparentValues = new ArrayList<>();
            traceparentValues.add("test-001"); // We can't do List.of() for null
            traceparentValues.add("");
            traceparentValues.add(null);
            for (String traceparentValue : traceparentValues) {
                try (
                    final TestRestClient client = cluster.getRestClient(USER_ADMIN, new BasicHeader(TRACEPARENT_HEADER, traceparentValue))
                ) {
                    Awaitility.await()
                        .alias("Wait for security to initialize")
                        .until(() -> client.securityHealth().getTextFromJsonBody("/status"), equalTo("UP"));

                    try (Client internalClient = cluster.getInternalNodeClient()) {
                        ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest().transientSettings(
                            Settings.builder().put(TOOKTIME_LOG_THRESHOLD, TimeValue.ZERO).build()
                        );
                        internalClient.admin().cluster().updateSettings(request).actionGet();
                    }

                    for (CharArrayWriter output : loggerOutputs.values()) {
                        output.reset();
                    }

                    TestRestClient.HttpResponse response = client.get("_cat/indices");
                    assertThat(response, isOk());

                    // Assert we see the relevant message at least once for each logger
                    for (Logger logger : loggerStrings.keySet()) {
                        CharArrayWriter output = loggerOutputs.get(logger);
                        String msg = getExpectedMessage(loggerStrings.get(logger), traceparentValue);
                        assertTrue(output.toString().contains(msg));
                        output.reset();
                    }

                    // Now set the threshold very high and assert we see no logs
                    try (Client internalClient = cluster.getInternalNodeClient()) {
                        ClusterUpdateSettingsRequest request = new ClusterUpdateSettingsRequest().transientSettings(
                            Settings.builder().put(TOOKTIME_LOG_THRESHOLD, new TimeValue(1, TimeUnit.DAYS)).build()
                        );
                        internalClient.admin().cluster().updateSettings(request).actionGet();
                    }
                    for (CharArrayWriter output : loggerOutputs.values()) {
                        output.reset();
                    }
                    response = client.get("_cat/indices");
                    assertThat(response, isOk());

                    for (Logger logger : loggerStrings.keySet()) {
                        CharArrayWriter output = loggerOutputs.get(logger);
                        String msg = getExpectedMessage(loggerStrings.get(logger), traceparentValue);
                        assertFalse(output.toString().contains(msg));
                        output.reset();
                    }
                }
            }
        }
    }

    private String getExpectedMessage(String baseMessage, String traceparentValue) {
        if (traceparentValue != null && !traceparentValue.isEmpty()) {
            baseMessage += " with traceparent header = " + traceparentValue;
        } else {
            baseMessage += " with no traceparent header";
        }
        return baseMessage;
    }
}
