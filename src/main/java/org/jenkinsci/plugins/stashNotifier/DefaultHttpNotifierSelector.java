package org.jenkinsci.plugins.stashNotifier;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * This is the default way of selecting a {@link HttpNotifier}.
 *
 * Always returns {@link DefaultApacheHttpNotifier} for backwards compatibility with v1.20 and earlier.
 */
class DefaultHttpNotifierSelector implements HttpNotifierSelector {
    private final HttpNotifier httpNotifier;

    DefaultHttpNotifierSelector(HttpNotifier httpNotifier) {
        this.httpNotifier = httpNotifier;
    }

    /**
     * @param context unused
     * @return singleton {@link DefaultApacheHttpNotifier}
     */
    @Override
    public @NonNull HttpNotifier select(@NonNull SelectionContext context) {
        return httpNotifier;
    }
}
