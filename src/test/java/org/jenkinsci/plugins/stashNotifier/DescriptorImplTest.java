package org.jenkinsci.plugins.stashNotifier;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;
import org.acegisecurity.Authentication;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.kohsuke.stapler.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

/**
 * Created by Vlad Medvedev on 27.01.2016.
 * vladislav.medvedev@devfactory.com
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({StashNotifier.DescriptorImpl.class, CredentialsProvider.class, Jenkins.class, TokenList.class})
public class DescriptorImplTest {

    /**
     * Class under test.
     */
    private StashNotifier.DescriptorImpl desc;

    private JSONObject json;
    private Jenkins jenkins;

    @Before
    public void setUp() {
        jenkins = PowerMockito.mock(Jenkins.class);

        PowerMockito.mockStatic(Jenkins.class);
        when(Jenkins.getInstance()).thenReturn(jenkins);

        json = new JSONObject();
        json.put("considerUnstableAsSuccess", "true");
        json.put("credentialsId", "bitbucket-credentials");
        json.put("disableInprogressNotification", "true");
        json.put("ignoreUnverifiedSsl", "true");
        json.put("includeBuildNumberInKey", "true");
        json.put("prependParentProjectKey", "true");
        json.put("projectKey", "JEN");
        json.put("stashRootUrl", "https://my.company.intranet/bitbucket");

        desc = spy(new StashNotifier.DescriptorImpl(false));
    }

    @Test
    public void testConfigure() throws Exception {
        //given
        doNothing().when(desc).save();

        ServletContext servletContext = mock(ServletContext.class);
        WebApp webApp = new WebApp(servletContext);

        Stapler stapler = mock(Stapler.class);
        when(stapler.getWebApp()).thenReturn(webApp);

        HttpServletRequest servletRequest = mock(HttpServletRequest.class);
        TokenList tokenList = mock(TokenList.class);

        RequestImpl staplerRequest = new RequestImpl(stapler, servletRequest, new ArrayList<>(), tokenList);

        //when
        desc.configure(staplerRequest, json);

        //then
        assertThat(desc.isApplicable(AbstractProject.class), is(true));
        assertThat(desc.getCredentialsId(), is("bitbucket-credentials"));
        assertThat(desc.isDisableInprogressNotification(), is(true));
        assertThat(desc.getDisplayName(), is("Notify Bitbucket Instance"));
        assertThat(desc.isIncludeBuildNumberInKey(), is(true));
        assertThat(desc.isIgnoreUnverifiedSsl(), is(true));
        assertThat(desc.isPrependParentProjectKey(), is(true));
        assertThat(desc.getStashRootUrl(), is("https://my.company.intranet/bitbucket"));
    }

    @Test
    public void test_doFillCredentialsIdItems_project_null() {
        //given
        when(jenkins.hasPermission(Item.CONFIGURE)).thenReturn(false);

        //when
        ListBoxModel listBoxModel = desc.doFillCredentialsIdItems(null);

        //then
        assertThat(listBoxModel, is(not(nullValue())));
    }

    @Test
    public void test_doFillCredentialsIdItems_no_permission() {
        //given
        Item project = mock(Item.class);
        when(project.hasPermission(Item.CONFIGURE)).thenReturn(false);
        when(jenkins.hasPermission(Item.CONFIGURE)).thenReturn(false);

        //when
        ListBoxModel listBoxModel = desc.doFillCredentialsIdItems(project);

        //then
        assertThat(listBoxModel, is(not(nullValue())));
    }

    @Test
    public void test_doFillCredentialsIdItems_has_permission() {
        //given
        Item project = mock(Item.class);
        when(project.hasPermission(Item.CONFIGURE)).thenReturn(true);
        PowerMockito.mockStatic(CredentialsProvider.class);
        PowerMockito.when(CredentialsProvider.lookupCredentials(
                any(),
                any(Item.class),
                any(Authentication.class),
                anyList()
        )).thenReturn(new ArrayList<>());

        //when
        ListBoxModel listBoxModel = desc.doFillCredentialsIdItems(project);

        //then
        assertThat(listBoxModel, is(not(nullValue())));
    }

    @Test
    public void test_doCheckStashServerBaseUrl_empty() throws Exception {
        //when
        FormValidation listBoxModel = desc.doCheckStashServerBaseUrl("");

        //then
        assertThat(listBoxModel.kind, is(FormValidation.Kind.ERROR));
    }

    @Test
    public void test_doCheckStashServerBaseUrl() throws Exception {
        //when
        FormValidation listBoxModel = desc.doCheckStashServerBaseUrl("https://my.company.intranet/bitbucket");

        //then
        assertThat(listBoxModel.kind, is(FormValidation.Kind.OK));
    }
}
