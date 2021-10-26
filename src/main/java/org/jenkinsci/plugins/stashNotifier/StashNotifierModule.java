package org.jenkinsci.plugins.stashNotifier;

import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import hudson.Extension;
import hudson.ExtensionList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Named;
import javax.inject.Singleton;
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
    HttpNotifier providesDefaultHttpNotifier() {
        return new DefaultApacheHttpNotifier();
    }

    @Provides
    @Singleton
    @StashNotifierDefault
    HttpNotifierSelector providesDefaultApacheHttpNotifierSelector(@StashNotifierDefault HttpNotifier httpNotifier) {
        return new DefaultHttpNotifierSelector(httpNotifier);
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
            LOGGER.info("Using {}", selectedClass.getName());
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
