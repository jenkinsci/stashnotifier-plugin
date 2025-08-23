package org.jenkinsci.plugins.stashNotifier.example;

import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import hudson.Extension;
import jakarta.inject.Singleton;

@Extension
public class LoggingNotifierModule extends AbstractModule {
    @Provides
    @Singleton
    LoggingHttpNotifierSelector providesLoggingNotifierSelector() {
        return new LoggingHttpNotifierSelector();
    }
}
