package org.jenkinsci.plugins.stashNotifier;

import com.google.common.collect.Lists;
import edu.umd.cs.findbugs.annotations.NonNull;
import net.sf.json.JSONObject;
import org.junit.Test;

import java.net.URI;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsSame.sameInstance;

public class StashNotifierModuleTest {
    private final StashNotifierModule module = new StashNotifierModule();
    private final HttpNotifierSelector fallback = new Fallback();
    private final HttpNotifierSelector preferred = new Preferred();
    private final List<HttpNotifierSelector> selectors = Lists.newArrayList(preferred, fallback);

    @Test
    public void shouldProvideDefaultApacheHttpNotifierSelectorIfPreferredNotFound() {
        HttpNotifierSelector actual = module.providesHttpNotifierSelector(
                fallback,
                "my.absent.plugin.MyHttpNotifierSelector",
                selectors
        );

        assertThat(actual, sameInstance(fallback));
    }

    @Test
    public void shouldProvideDefaultApacheHttpNotifierSelectorIfPreferredNotSet() {
        HttpNotifierSelector actual = module.providesHttpNotifierSelector(
                fallback,
                "",
                selectors
        );

        assertThat(actual, sameInstance(fallback));
    }

    @Test
    public void shouldProvidePreferredHttpNotifierSelectorIfSet() {
        HttpNotifierSelector actual = module.providesHttpNotifierSelector(
                fallback,
                Preferred.class.getName(),
                selectors
        );

        assertThat(actual, sameInstance(preferred));
    }

    private static class Preferred implements HttpNotifierSelector {
        @NonNull
        @Override
        public HttpNotifier select(@NonNull SelectionContext context) {
            return new AlwaysSucceedsHttpNotifier();
        }
    }

    private static class Fallback implements HttpNotifierSelector {
        @NonNull
        @Override
        public HttpNotifier select(@NonNull SelectionContext context) {
            return new AlwaysSucceedsHttpNotifier();
        }
    }

    private static class AlwaysSucceedsHttpNotifier implements HttpNotifier {
        @Override
        public @NonNull NotificationResult send(@NonNull URI uri, @NonNull JSONObject payload, @NonNull NotificationSettings settings, @NonNull NotificationContext context) {
            return NotificationResult.newSuccess();
        }
    }
}
