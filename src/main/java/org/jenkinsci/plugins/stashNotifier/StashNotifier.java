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
 
import hudson.Extension;
import hudson.Launcher;
import hudson.model.BuildListener;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.plugins.git.util.BuildData;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.BuildStepMonitor;
import hudson.tasks.Notifier;
import hudson.tasks.Publisher;
import hudson.util.FormValidation;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URL;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.servlet.ServletException;

import jenkins.model.Jenkins;
import net.sf.json.JSONObject;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.util.EntityUtils;
import org.jenkinsci.plugins.stashNotifier.util.BasicStashRequestConfigurator;
import org.jenkinsci.plugins.stashNotifier.util.BuildEntityFactory;
import org.jenkinsci.plugins.stashNotifier.util.ConcreteHttpClientFactory;
import org.jenkinsci.plugins.stashNotifier.util.HttpClientFactory;
import org.jenkinsci.plugins.stashNotifier.util.JsonBuildEntityFactory;
import org.jenkinsci.plugins.stashNotifier.util.StashRequestConfigurator;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

/**
 * Notifies a configured Atlassian Stash server instance of build results
 * through the Stash build API.
 * <p>
 * Only basic authentication is supported at the moment.
 * 
 * @author	Georg Gruetter
 */
public class StashNotifier extends Notifier {
	
	// attributes --------------------------------------------------------------

	/** base url of Stash server, e. g. <tt>http://localhost:7990</tt>. */
	private final String stashServerBaseUrl;
	
	/** name of Stash user for authentication with Stash build API. */
	private final String stashUserName;
	
	/** password of Stash user for authentication with Stash build API. */
	private final String stashUserPassword;
	
	/** if true, ignore exception thrown in case of an unverified SSL peer. */
	private final boolean ignoreUnverifiedSSLPeer;
	
	private HttpClientFactory httpClientfactory;
	
	private BuildEntityFactory buildEntityFactory;
	
	private StashRequestConfigurator requestConfigurator;
	
	// public members ----------------------------------------------------------

	public BuildStepMonitor getRequiredMonitorService() {
		return BuildStepMonitor.BUILD;
	}

	@DataBoundConstructor
	public StashNotifier(
			String stashServerBaseUrl,
			String stashUserName,
			String stashUserPassword,
			boolean ignoreUnverifiedSSLPeer) {
		this.stashServerBaseUrl = stashServerBaseUrl;
		this.stashUserName = stashUserName;
		this.stashUserPassword = stashUserPassword;
		this.ignoreUnverifiedSSLPeer 
			= ignoreUnverifiedSSLPeer;
		
		httpClientfactory = new ConcreteHttpClientFactory();
		buildEntityFactory = new JsonBuildEntityFactory();
		requestConfigurator = new BasicStashRequestConfigurator(stashUserName, 
				stashUserPassword);
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
	
	public boolean getIgnoreUnverifiedSSLPeer() {
		return ignoreUnverifiedSSLPeer;
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

		// get the sha1 of the commit that was built
		BuildData buildData 
			= (BuildData) build.getAction(BuildData.class);
		
		if  (buildData != null) {
			String commitSha1 
				= buildData.getLastBuiltRevision().getSha1String();
			
			HttpClient client = httpClientfactory.getHttpClient(
					getStashServerBaseUrl().startsWith("https"),
					ignoreUnverifiedSSLPeer, 
					logger);
			NotificationResult result;

			try {
				result = notifyStash(build, commitSha1, client);
				if (result.indicatesSuccess) {
					logger.println(
						"Notified Stash for commit with id " 
								+ commitSha1);
				} else {
					logger.println(
					"Failed to notify Stash for commit "
							+ commitSha1
							+ " (" + result.message + ")");
				}					
            } catch (SSLPeerUnverifiedException e) {
	    		logger.println("SSLPeerUnverifiedException caught while "
    				+ "notifying Stash. Make sure your SSL certificate on "
    				+ "your Stash server is valid or check the "
    				+ " 'Ignore unverifiable SSL certificate' checkbox in the "
    				+ "Stash plugin configuration of this job.");
			} catch (Exception e) {
				logger.println(
						"Caught exception while notifying Stash: " 
						+ e.getMessage());
			} finally {
				client.getConnectionManager().shutdown();
			}			
		} else {
			logger.println(
					"found no commit info");
		}
		return true;
	}
		
	
	@Extension 
	public static final class DescriptorImpl 
		extends BuildStepDescriptor<Publisher> {

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
	 * @param commitSha1	the SHA1 of the built commit
	 * @param client		the HTTP client with which to execute the request
	 * @param listener		the build listener for logging
	 */
	@SuppressWarnings("rawtypes")
	private NotificationResult notifyStash(
			final AbstractBuild build,
			final String commitSha1,
			final HttpClient client) throws Exception {
		
		String url = stashServerBaseUrl + 
				"/rest/build-status/1.0/commits/" + commitSha1;
		HttpPost req = new HttpPost(url);
		requestConfigurator.configureStashRequest(req);
		req.addHeader("Content-type", "application/json");		
		req.setEntity(buildEntityFactory
				.createBuildEntity(Jenkins.getInstance(), build));
		
		HttpResponse res = client.execute(req);
		if (res.getStatusLine().getStatusCode() != 204) {
			return NotificationResult.newFailure(
					EntityUtils.toString(res.getEntity()));
		} else {
			return NotificationResult.newSuccess();
		}
	}
	
}
