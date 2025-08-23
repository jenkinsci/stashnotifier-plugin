package org.jenkinsci.plugins.stashNotifier.example;

import java.io.PrintStream;
import java.net.URI;

import org.jenkinsci.plugins.stashNotifier.HttpNotifier;
import org.jenkinsci.plugins.stashNotifier.NotificationContext;
import org.jenkinsci.plugins.stashNotifier.NotificationResult;
import org.jenkinsci.plugins.stashNotifier.NotificationSettings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.cloudbees.plugins.credentials.Credentials;

import edu.umd.cs.findbugs.annotations.NonNull;
import net.sf.json.JSONObject;

/**
 * Included as an example to demonstrate how alternative notifiers work.
 * Set the system property <code>-Dorg.jenkinsci.plugins.stashNotifier.HttpNotifierSelector.className=org.jenkinsci.plugins.stashNotifier.example.LoggingHttpNotifierSelector<code>
 * to tell the system to choose this implementation.
 */
class LoggingHttpNotifier implements HttpNotifier {
    private static final Logger LOGGER = LoggerFactory.getLogger(LoggingHttpNotifier.class);

    @Override
    public @NonNull NotificationResult send(@NonNull URI uri, @NonNull JSONObject payload, @NonNull NotificationSettings settings, @NonNull NotificationContext context) {
        Credentials creds = settings.getCredentials();
        String runId = context.getRunId();
        PrintStream buildLog = context.getLogger();
        String target = uri == null ? "(undefined)" : uri.toASCIIString();
        buildLog.println("[stash-notifier] would have notified " + target + " with " + payload);
        if (creds != null) {
            Class<?> credsClass = creds.getClass();
            LOGGER.info("{} would have used {} to notify {} with payload {}", runId, credsClass.getSimpleName(), target, payload);
        } else {
            LOGGER.info("{} would have notified {} with payload {}", runId, target, payload);
        }
        return NotificationResult.newSuccess();
    }
}
