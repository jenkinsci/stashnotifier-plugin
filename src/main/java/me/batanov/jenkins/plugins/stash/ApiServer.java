package me.batanov.jenkins.plugins.stash;

import org.apache.http.auth.AuthenticationException;

import javax.annotation.Nonnull;
import java.util.Map;

/**
 * @author Pavel Batanov <pavel@batanov.me>
 *         2016-01-10 15:42 15:44
 */
public interface ApiServer {
    @Nonnull
    Map<String, Object> performApiCall(String method, @Nonnull Map<String, Object> map) throws AuthenticationException;
}
