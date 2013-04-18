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

import org.apache.http.client.HttpClient;
import org.jenkinsci.plugins.stashNotifier.util.BasicStashRequestConfigurator;
import org.jenkinsci.plugins.stashNotifier.util.ConcreteHttpClientFactory;
import org.jenkinsci.plugins.stashNotifier.util.ConfigurableStashNotifierService;
import org.jenkinsci.plugins.stashNotifier.util.HttpClientFactory;
import org.jenkinsci.plugins.stashNotifier.util.JsonBuildEntityFactory;
import org.jenkinsci.plugins.stashNotifier.util.StashNotifierService;
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
	
	private Jenkins jenkins;
	
	private StashNotifierService notifierService;
	
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
		this.ignoreUnverifiedSSLPeer = ignoreUnverifiedSSLPeer;
		
		httpClientfactory = new ConcreteHttpClientFactory();
		notifierService = new ConfigurableStashNotifierService(
				stashServerBaseUrl, 
				new JsonBuildEntityFactory(), 
				new BasicStashRequestConfigurator(stashUserName, 
						stashUserPassword));
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
		if (getJenkins().getRootUrl() == null) {
			logger.println(
					"Cannot notify Stash! (Jenkins Root URL not configured)");
			return true;
		}

		// get the sha1 of the commit that was built
		BuildData buildData = (BuildData) build.getAction(BuildData.class);
		if (buildData == null) {
			logger.println("found no commit info");
			return true;
		}

		String commitSha1 = buildData.getLastBuiltRevision().getSha1String();
		
		HttpClient client = httpClientfactory.getHttpClient(
				getStashServerBaseUrl().startsWith("https"),
				ignoreUnverifiedSSLPeer, 
				logger);

		try {
			NotificationResult result = 
					notifierService.notifyStash(build, commitSha1, client);
			String message;
			if (result.indicatesSuccess) {
				message = "Notified Stash for commit with id " + commitSha1;
			} else {
				message = "Failed to notify Stash for commit "
						+ commitSha1 
						+ " (" + result.message + ")";
			}					
			logger.println(message);
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
		public boolean configure(StaplerRequest req, JSONObject formData) 
				throws FormException {
			
			save();
			return super.configure(req,formData);
		}
	}
	
	/**
	 * Added for testing purposes
	 */
	protected void setHttpClientfactory(HttpClientFactory httpClientfactory) {
		this.httpClientfactory = httpClientfactory;
	}
	
	/**
	 * Added for testing purposes
	 */
	protected void setJenkins(Jenkins jenkins) {
		this.jenkins = jenkins;
	}
	
	/**
	 * Get the current Jenkins instance.
	 */
	private Jenkins getJenkins() {
		if (jenkins == null)
			jenkins = Jenkins.getInstance();
		return jenkins;
	}
	
	/**
	 * Added for testing purposes
	 */
	protected void setNotifierService(StashNotifierService notifierService) {
		this.notifierService = notifierService;
	}
	
}
