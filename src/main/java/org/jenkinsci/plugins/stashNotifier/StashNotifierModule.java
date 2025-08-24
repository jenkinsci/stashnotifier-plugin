package org.jenkinsci.plugins.stashNotifier;

import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import hudson.Extension;
import hudson.ExtensionList;
import org.jenkinsci.plugins.stashNotifier.NotifierSelectors.DefaultHttpNotifierSelector;
import org.jenkinsci.plugins.stashNotifier.NotifierSelectors.HttpNotifierSelector;
import org.jenkinsci.plugins.stashNotifier.Notifiers.DefaultApacheHttpNotifier;
import org.jenkinsci.plugins.stashNotifier.Notifiers.ExtendedApacheHttpNotifier;
import org.jenkinsci.plugins.stashNotifier.Notifiers.HttpNotifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.inject.Named;
import jakarta.inject.Singleton;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Extension
public class StashNotifierModule extends AbstractModule {
    private static final Logger LOGGER = LoggerFactory.getLogger(StashNotifierModule.class);

    @Override
    protected void configure() {
    }

    @Provides
    @Singleton
    @StashNotifierDefault
    List<HttpNotifier> providesDefaultHttpNotifiers() {
        return new ArrayList<>(Arrays.asList(new DefaultApacheHttpNotifier(), new ExtendedApacheHttpNotifier()));
    }

    @Provides
    @Singleton
    @StashNotifierDefault
    HttpNotifierSelector providesDefaultApacheHttpNotifierSelector(@StashNotifierDefault List<HttpNotifier> httpNotifiers) {
        return new DefaultHttpNotifierSelector(httpNotifiers);
    }

    @Provides
    List<HttpNotifierSelector> providesHttpNotifierSelectors() {
        return ExtensionList.lookup(HttpNotifierSelector.class);
    }

    @Provides
    @Singleton
    HttpNotifierSelector providesHttpNotifierSelector(@StashNotifierDefault HttpNotifierSelector fallback,
                                                      @Named("preferredHttpNotifierSelector") String preferredHttpNotifierSelector,
                                                      List<HttpNotifierSelector> httpNotifierSelectors) {
        HttpNotifierSelector selector = httpNotifierSelectors.stream()
                .filter(s -> s.getClass().getName().equals(preferredHttpNotifierSelector))
                .findFirst()
                .orElse(fallback);
        Class<? extends HttpNotifierSelector> selectedClass = selector.getClass();
        if (selectedClass.getName().equals(preferredHttpNotifierSelector)) {
            LOGGER.debug("Using {}", selectedClass.getName());
        } else {
            LOGGER.warn("{} not found - using {}", preferredHttpNotifierSelector, selectedClass.getName());
        }
        return selector;
    }

    @Provides
    @Singleton
    @Named("preferredHttpNotifierSelector")
    String providesPreferredHttpNotifierSelector() {
        String override = HttpNotifierSelector.class.getName() + ".className";
        return System.getProperty(override, DefaultHttpNotifierSelector.class.getName());
    }
}
