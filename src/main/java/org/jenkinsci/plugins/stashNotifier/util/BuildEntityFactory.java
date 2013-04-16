package org.jenkinsci.plugins.stashNotifier.util;

import hudson.model.AbstractBuild;
import jenkins.model.Jenkins;

import org.apache.http.HttpEntity;

/**
 * Factory interface to be used to create a HTTP entity body for the POST to
 * Stash.
 * 
 * @author Michael Irwin
 */
public interface BuildEntityFactory {

	/**
	 * Returns the content type MIME for the type of entity that is created by
	 * this factory.
	 * @return The content type MIME for the type of entity created.
	 */
	String getContentType();
	
	/**
	 * Create an entity object that should be sent to Stash containing the
	 * information about this build.
	 * @param jenkins the current Jenkins model instance
	 * @param build the build to notify Stash of
	 * @return HTTP entity body that can be POST'ed to the Stash build API
	 * @throws Exception Any exception
	 */
	@SuppressWarnings("rawtypes")
	HttpEntity createBuildEntity(Jenkins jenkins, AbstractBuild build) 
			throws Exception;
	
}
