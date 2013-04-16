package org.jenkinsci.plugins.stashNotifier.util;

import hudson.model.Result;
import hudson.model.AbstractBuild;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;

import org.apache.commons.lang.StringEscapeUtils;
import org.apache.http.HttpEntity;
import org.apache.http.entity.StringEntity;

/**
 * An implementation of the {@link BuildEntityFactory} that creates a JSON
 * representation of the build result to be sent to the Stash Build API.
 * 
 * @author Michael Irwin
 */
public class JsonBuildEntityFactory implements BuildEntityFactory {

	public String getContentType() {
		return "application/json";
	}
	
	/**
	 * {@inheritDoc}
	 */
	@SuppressWarnings("rawtypes")
	public HttpEntity createBuildEntity(Jenkins jenkins, AbstractBuild build) 
			throws Exception {
		JSONObject json = new JSONObject();

        json.put("state", getBuildState(build.getResult()));
        json.put("key", escape(build.getProject().getName()));

        // This is to replace the odd character Jenkins injects to separate 
        // nested jobs, especially when using the Cloudbees Folders plugin. 
        // These characters cause Stash to throw up.
        String fullName = escape(build.getFullDisplayName()).
                replaceAll("\\\\u00BB", "\\/");
        json.put("name", fullName);

        String baseUrl = jenkins.getRootUrl();
        json.put("description", "built by Jenkins @ ".concat(baseUrl));
        json.put("url", baseUrl.concat(build.getUrl()));
        
        return new StringEntity(json.toString());
	}
	
	protected String getBuildState(Result result) {
		if (result != null && result.equals(Result.SUCCESS))
			return "SUCCESSFUL";
		return "FAILED";
	}
	
	protected String escape(String data) {
		return StringEscapeUtils.escapeJavaScript(data);
	}

}
