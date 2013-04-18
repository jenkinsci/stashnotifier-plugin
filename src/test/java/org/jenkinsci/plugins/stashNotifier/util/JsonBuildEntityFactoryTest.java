package org.jenkinsci.plugins.stashNotifier.util;

import hudson.model.Result;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import jenkins.model.Jenkins;
import junit.framework.TestCase;
import net.sf.json.JSONObject;

import org.apache.http.HttpEntity;
import org.apache.http.util.EntityUtils;
import org.mockito.Mockito;

public class JsonBuildEntityFactoryTest extends TestCase {

	private JsonBuildEntityFactory factory;
	
	@Override
	protected void setUp() throws Exception {
		super.setUp();
		factory = new JsonBuildEntityFactory();
	}
	
	public void testSettingState() {
		assertEquals("FAILED", factory.getBuildState(null));
		assertEquals("FAILED", factory.getBuildState(Result.ABORTED));
		assertEquals("FAILED", factory.getBuildState(Result.FAILURE));
		assertEquals("FAILED", factory.getBuildState(Result.NOT_BUILT));
		assertEquals("FAILED", factory.getBuildState(Result.UNSTABLE));
		assertEquals("SUCCESSFUL", factory.getBuildState(Result.SUCCESS));
	}
	
	public void testContentType() {
		assertEquals("application/json", factory.getContentType());
	}
	
	@SuppressWarnings("rawtypes")
	public void testBuildEntity() throws Exception {
		String rootUrl = "http://jenkins.localhost/";
		Result result = Result.SUCCESS;
		String projectName = "project-name";
		String fullDisplayName = "Project Name";
		String buildUrl = "/job/project-name/1";
		
		Jenkins jenkins = Mockito.mock(Jenkins.class);
		Mockito.when(jenkins.getRootUrl()).thenReturn(rootUrl);
		
		AbstractProject project = Mockito.mock(AbstractProject.class);
		Mockito.when(project.getName()).thenReturn(projectName);
		
		AbstractBuild build = Mockito.mock(AbstractBuild.class);
		Mockito.when(build.getResult()).thenReturn(result);
		Mockito.when(build.getProject()).thenReturn(project);
		Mockito.when(build.getFullDisplayName()).thenReturn(fullDisplayName);
		Mockito.when(build.getUrl()).thenReturn(buildUrl);

		HttpEntity entity = factory.createBuildEntity(jenkins, build);
		JSONObject object = JSONObject.fromObject(EntityUtils.toString(entity));
		
		assertEquals(factory.getBuildState(result), object.getString("state"));
		assertEquals(factory.escape(projectName) + "-" + rootUrl, 
				object.getString("key"));
		assertEquals(factory.escape(fullDisplayName), object.getString("name"));
		assertEquals("built by Jenkins @ ".concat(rootUrl), 
				object.getString("description"));
		assertEquals(rootUrl.concat(buildUrl), object.getString("url"));
	}
	
}
