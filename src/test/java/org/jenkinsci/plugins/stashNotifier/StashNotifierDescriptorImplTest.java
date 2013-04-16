package org.jenkinsci.plugins.stashNotifier;

import hudson.util.FormValidation;
import hudson.util.FormValidation.Kind;
import junit.framework.TestCase;

import org.jenkinsci.plugins.stashNotifier.StashNotifier.DescriptorImpl;

/**
 * Test case for the StashNotifier.DescriptorImpl class
 * 
 * @author Michael Irwin
 */
public class StashNotifierDescriptorImplTest extends TestCase {

	private DescriptorImpl descriptor;
	
	@Override
	protected void setUp() throws Exception {
		super.setUp();
		descriptor = new DescriptorImpl();
	}
	
	public void testInvalidServerBaseUrl() throws Exception {
		FormValidation validation = descriptor.doCheckStashServerBaseUrl("nothing");
		assertEquals(Kind.ERROR, validation.kind);
		assertEquals("Please specify a valid URL!", validation.getMessage());
	}
	
	public void testValidServerBaseUrl() throws Exception {
		FormValidation validation = 
				descriptor.doCheckStashServerBaseUrl("http://google.com/");
		assertEquals(Kind.OK, validation.kind);
	}
	
	public void testInvalidUsername() throws Exception {
		FormValidation validation = descriptor.doCheckStashUserName("");
		assertEquals(Kind.ERROR, validation.kind);
		assertEquals("Please specify a user name!", validation.getMessage());
	}

	public void testValidUsername() throws Exception {
		FormValidation validation = descriptor.doCheckStashUserName("username");
		assertEquals(Kind.OK, validation.kind);
	}
	
	public void testInvalidPassword() throws Exception {
		FormValidation validation = descriptor.doCheckStashUserPassword("");
		assertEquals(Kind.WARNING, validation.kind);
		assertEquals("You should use a non-empty password!", validation.getMessage());
	}

	public void testValidPassword() throws Exception {
		FormValidation validation = 
				descriptor.doCheckStashUserPassword("Passw0rd");
		assertEquals(Kind.OK, validation.kind);
	}
	
	public void testDisplayName() {
		assertEquals("Notify Stash Instance", descriptor.getDisplayName());
	}
	
	public void testIsApplicable() {
		assertTrue(descriptor.isApplicable(null));
	}
	
}
