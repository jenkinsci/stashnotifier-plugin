package org.jenkinsci.plugins.stashNotifier;

import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import hudson.Extension;

import javax.inject.Named;
import javax.inject.Singleton;

@Extension
public class StashNotifierModule extends AbstractModule {
    @Override
    protected void configure() {
    }

    @Provides
    @Singleton
    @Named("defaultApache")
    HttpNotifier providesDefaultApacheHttpNotifier() {
        return new DefaultApacheHttpNotifier();
    }

    @Provides
    HttpNotifierSelector providesHttpNotifierSelector(@Named("defaultApache") HttpNotifier httpNotifier) {
        return new DefaultHttpNotifierSelector(httpNotifier);
    }
}
