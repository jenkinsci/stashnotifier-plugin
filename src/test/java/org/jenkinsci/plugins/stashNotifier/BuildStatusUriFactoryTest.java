package org.jenkinsci.plugins.stashNotifier;

import org.junit.Test;

import java.net.URI;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.junit.Assert.*;

public class BuildStatusUriFactoryTest {

    @Test
    public void shouldHandleTrailingSlash() {
        String baseUri = "http://localhost:12345/";
        URI expected = URI.create("http://localhost:12345/rest/build-status/1.0/commits/25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        URI actual = BuildStatusUriFactory.create(baseUri, "25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        assertThat(actual, equalTo(expected));
    }

    @Test
    public void shouldHandleNoTrailingSlash() {
        String baseUri = "http://localhost:12345";
        URI expected = URI.create("http://localhost:12345/rest/build-status/1.0/commits/25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        URI actual = BuildStatusUriFactory.create(baseUri, "25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        assertThat(actual, equalTo(expected));
    }

    @Test
    public void shouldHandleBasePathTrailingSlash() {
        String baseUri = "http://localhost:12345/some-path/";
        URI expected = URI.create("http://localhost:12345/some-path/rest/build-status/1.0/commits/25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        URI actual = BuildStatusUriFactory.create(baseUri, "25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        assertThat(actual, equalTo(expected));
    }

    @Test
    public void shouldHandleBasePathNoTrailingSlash() {
        String baseUri = "http://localhost:12345/some-path";
        URI expected = URI.create("http://localhost:12345/some-path/rest/build-status/1.0/commits/25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        URI actual = BuildStatusUriFactory.create(baseUri, "25a4b3c9b494fc7ac65b80e3b0ecce63f235f20d");
        assertThat(actual, equalTo(expected));
    }
}
