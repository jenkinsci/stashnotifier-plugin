package org.jenkinsci.plugins.stashNotifier.example;

import org.jenkinsci.plugins.stashNotifier.HttpNotifier;
import org.jenkinsci.plugins.stashNotifier.HttpNotifierSelector;
import org.jenkinsci.plugins.stashNotifier.SelectionContext;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * This is an example alternative way of selecting a {@link HttpNotifier}.
 */
class LoggingHttpNotifierSelector implements HttpNotifierSelector {

    /**
     * @param context unused
     * @return {@link LoggingHttpNotifier}
     */
    @Override
    public @NonNull HttpNotifier select(@NonNull SelectionContext context) {
        return new LoggingHttpNotifier();
    }
}
