package org.jenkinsci.plugins.stashNotifier.NotifierSelectors;

import edu.umd.cs.findbugs.annotations.NonNull;
import org.jenkinsci.plugins.stashNotifier.Notifiers.DefaultApacheHttpNotifier;
import org.jenkinsci.plugins.stashNotifier.Notifiers.ExtendedApacheHttpNotifier;
import org.jenkinsci.plugins.stashNotifier.Notifiers.HttpNotifier;
import org.jenkinsci.plugins.stashNotifier.SelectionContext;

import java.util.*;

public class DefaultHttpNotifierSelector implements HttpNotifierSelector {
    private final List<HttpNotifier> httpNotifiers;

    public DefaultHttpNotifierSelector(List<HttpNotifier> notifiers) {
        httpNotifiers = notifiers;
    }

    public DefaultHttpNotifierSelector(HttpNotifier notifier) {
        httpNotifiers = new ArrayList<>();
        httpNotifiers.add(notifier);
    }

    @Override
    public HttpNotifier select(@NonNull SelectionContext context) {
        if(context.getBitBucketProjectKey() == null || context.getBitBucketProjectKey().isEmpty() || context.getBitBucketProjectSlug() == null || context.getBitBucketProjectSlug().isEmpty())
        {
            Optional<HttpNotifier> defaultNotifier = httpNotifiers.stream().filter(hn -> hn.getClass().getName().equals(DefaultApacheHttpNotifier.class.getName())).findFirst();
            if(defaultNotifier.isPresent()) {
                return defaultNotifier.get();
            }
        }

        Optional<HttpNotifier> extendedNotifier = httpNotifiers.stream().filter(hn -> hn.getClass().getName().equals(ExtendedApacheHttpNotifier.class.getName())).findFirst();

        return extendedNotifier.orElseGet(() -> httpNotifiers.get(0));
    }
}
