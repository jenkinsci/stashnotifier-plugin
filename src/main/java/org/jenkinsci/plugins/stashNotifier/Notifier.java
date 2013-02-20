/*
 * Copyright 2013 Georg Gruetter
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 package org.jenkinsci.plugins.stashNotifier;
 
import hudson.Launcher;
import hudson.Extension;
import hudson.util.FormValidation;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.AbstractProject;
import hudson.model.Result;
import hudson.plugins.git.GitChangeSet;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import net.sf.json.JSONObject;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.QueryParameter;

import javax.servlet.ServletException;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URL;

import jenkins.model.Jenkins;

/**
 * Notifies a configured Atlassian Stash server instance of build results
 * through the Stash build API.
 * <p>
 * Only basic authentication is supported at the moment.
 * 
 * @author	Georg Gruetter
 */
public class Notifier extends Builder {
	
	// attributes --------------------------------------------------------------

	/** base url of Stash server, e. g. <tt>http://localhost:7990</tt>. */
	private final String stashServerBaseUrl;
	
	/** name of Stash user for authentication with Stash build API. */
	private final String stashUserName;
	
	/** password of Stash user for authentication with Stash build API. */
	private final String stashUserPassword;
	
	// public members ----------------------------------------------------------

	@DataBoundConstructor
	public Notifier(
			String stashServerBaseUrl,
			String stashUserName,
			String stashUserPassword) {
		this.stashServerBaseUrl = stashServerBaseUrl;
		this.stashUserName = stashUserName;
		this.stashUserPassword = stashUserPassword;
	}

	public String getStashServerBaseUrl() {
		return stashServerBaseUrl;
	}

	public String getStashUserName() {
		return stashUserName;
	}

	public String getStashUserPassword() {
		return stashUserPassword;
	}

	@SuppressWarnings("rawtypes")
	@Override
	public boolean perform(
			AbstractBuild build, 
			Launcher launcher, 
			BuildListener listener) {
		
		PrintStream logger = listener.getLogger();

		// exit if Jenkins root URL is not configured. Stash build API 
		// requires valid link to build in CI system.
		if (Jenkins.getInstance().getRootUrl() == null) {
			logger.println(
					"Cannot notify Stash! (Jenkins Root URL not configured)");
			return true;
		}

		
		// notify Stash instance for each item in the change set of this
		// build if the item is a {@link GitChangeSet} instance. Other
		// types of change sets are ignored.
		
		HttpClient client = new DefaultHttpClient();
		NotificationResult result;
		GitChangeSet gitChangeSet;
		
		try {
			for (Object changeSet: build.getChangeSet().getItems()) {
				if (changeSet instanceof GitChangeSet) {
					gitChangeSet = (GitChangeSet) changeSet;
					result = notifyStash(build, gitChangeSet, client, listener);
					if (result.indicatesSuccess) {
						logger.println(
							"Notified Stash for commit with id " 
									+ gitChangeSet.getCommitId());
					} else {
						logger.println(
						"Failed to notify Stash for commit "
								+ gitChangeSet.getCommitId() 
								+ " (" + result.message + ")");
					}
				} else {
					logger.println("ignored change set (not a git changeset)");
				}
			}
		} catch (Exception e) {
			logger.println(
					"Caught exception while notifying Stash: " 
					+ e.getMessage());
		} finally {
			client.getConnectionManager().shutdown();
		}
		
		return true;
	}


	@Extension 
	public static final class DescriptorImpl 
		extends BuildStepDescriptor<Builder> {

		public FormValidation doCheckStashServerBaseUrl(
					@QueryParameter String value) 
				throws IOException, ServletException {

			try {
				new URL(value);
				return FormValidation.ok();
			} catch (Exception e) {
				return FormValidation.error("Please specify a valid URL!");
			}
		}

		public FormValidation doCheckStashUserName(@QueryParameter String value)
				throws IOException, ServletException {

			if (value.trim().equals("")) {
				return FormValidation.error("Please specify a user name!");
			} else {
				return FormValidation.ok();
			}
		}

		public FormValidation doCheckStashUserPassword(
					@QueryParameter String value) 
				throws IOException, ServletException {

			if (value.trim().equals("")) {
				return FormValidation.warning(
						"You should use a non-empty password!");
			} else {
				return FormValidation.ok();
			}
		}

		@SuppressWarnings("rawtypes")
		public boolean isApplicable(Class<? extends AbstractProject> aClass) {
			return true;
		}

		public String getDisplayName() {
			return "Notify Stash Instance";
		}

		@Override
		public boolean configure(
				StaplerRequest req, 
				JSONObject formData) throws FormException {

			save();
			return super.configure(req,formData);
		}
	}
	
	// non-public members ------------------------------------------------------
	
	/**
	 * Notifies the configured Stash server by POSTing the build results 
	 * to the Stash build API.
	 * 
	 * @param build			the build to notify Stash of
	 * @param changeSet		the built change set
	 * @param client		the HTTP client with which to execute the request
	 * @param listener		the build listener for logging
	 */
	@SuppressWarnings("rawtypes")
	private NotificationResult notifyStash(
			final AbstractBuild build,
			final GitChangeSet changeSet,
			final HttpClient client, 
			final BuildListener listener) throws Exception {
		
		HttpPost req = createRequest(build, changeSet);
		HttpResponse res = client.execute(req);
		if (res.getStatusLine().getStatusCode() != 204) {
			return NotificationResult.newFailure(
					EntityUtils.toString(res.getEntity()));
		} else {
			return NotificationResult.newSuccess();
		}
	}
	
	/**
	 * Returns the HTTP POST request ready to be sent to the Stash build API for
	 * the given build and change set. 
	 * 
	 * @param build			the build to notify Stash of
	 * @param changeSet		the change set that was built
	 * @return				the HTTP POST request to the Stash build API
	 */
	@SuppressWarnings("rawtypes")
	private HttpPost createRequest(
			final AbstractBuild build,
			final GitChangeSet changeSet) throws Exception {
		
		HttpPost req = new HttpPost(
				stashServerBaseUrl  
				+ "/rest/build-status/1.0/commits/" 
				+ changeSet.getCommitId());
		
		req.addHeader(BasicScheme.authenticate(
				new UsernamePasswordCredentials(
						stashUserName, 
						stashUserPassword), 
				"UTF-8", 
				false));
		
		req.addHeader("Content-type", "application/json");		
		req.setEntity(newStashBuildNotificationEntity(build));
				
		return req;
	}
	
	/**
	 * Returns the HTTP POST entity body with the JSON representation of the
	 * builds result to be sent to the Stash build API.
	 * 
	 * @param build			the build to notify Stash of
	 * @return				HTTP entity body for POST to Stash build API
	 */
	@SuppressWarnings("rawtypes")
	private HttpEntity newStashBuildNotificationEntity(
			final AbstractBuild build) throws Exception {
		
		StringBuilder builder = new StringBuilder();
		builder.append("{\"state\":\"");

		if ((build.getResult() == null) 
				|| (!build.getResult().equals(Result.SUCCESS))) {
			builder.append("FAILED");
		} else {
			builder.append("SUCCESSFUL");
		}

		builder.append("\", \"key\":\"");
		builder.append(build.getProject().getName());
		
		builder.append("\", \"name\":\"");
		builder.append(build.getFullDisplayName());

		builder.append("\", \"description\":\"built by Jenkins @ ");
		builder.append(Jenkins.getInstance().getRootUrl());

		builder.append("\", \"url\":\"");
		builder.append(Jenkins.getInstance().getRootUrl());
		builder.append(build.getUrl());

		builder.append("\"}");
		
		return new StringEntity(builder.toString());
	}
}

