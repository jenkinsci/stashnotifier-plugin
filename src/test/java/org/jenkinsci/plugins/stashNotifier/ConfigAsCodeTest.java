package org.jenkinsci.plugins.stashNotifier;

import io.jenkins.plugins.casc.ConfigurationContext;
import io.jenkins.plugins.casc.ConfiguratorRegistry;
import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import io.jenkins.plugins.casc.misc.junit.jupiter.WithJenkinsConfiguredWithCode;
import io.jenkins.plugins.casc.model.CNode;
import org.junit.jupiter.api.Test;

import static io.jenkins.plugins.casc.misc.Util.getUnclassifiedRoot;
import static io.jenkins.plugins.casc.misc.Util.toStringFromYamlFile;
import static io.jenkins.plugins.casc.misc.Util.toYamlString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.Is.is;

@WithJenkinsConfiguredWithCode
class ConfigAsCodeTest {

    @Test
    @ConfiguredWithCode("configuration-as-code.yml")
    void should_support_jcasc_from_yaml(JenkinsConfiguredWithCodeRule rule) {
        StashNotifier.DescriptorImpl stashNotifierConfig = rule.jenkins.getDescriptorByType(StashNotifier.DescriptorImpl.class);

        assertThat(stashNotifierConfig.isConsiderUnstableAsSuccess(), equalTo(true));
        assertThat(stashNotifierConfig.getCredentialsId(), equalTo("bitbucket-credentials"));
        assertThat(stashNotifierConfig.isDisableInprogressNotification(), equalTo(true));
        assertThat(stashNotifierConfig.isIgnoreUnverifiedSsl(), equalTo(true));
        assertThat(stashNotifierConfig.isIncludeBuildNumberInKey(), equalTo(true));
        assertThat(stashNotifierConfig.isPrependParentProjectKey(), equalTo(true));
        assertThat(stashNotifierConfig.getStashRootUrl(), equalTo("https://my.company.intranet/bitbucket"));
    }

    @Test
    @ConfiguredWithCode("configuration-as-code.yml")
    void should_support_jcasc_to_yaml(JenkinsConfiguredWithCodeRule rule) throws Exception {
        ConfiguratorRegistry registry = ConfiguratorRegistry.get();
        ConfigurationContext context = new ConfigurationContext(registry);
        CNode yourAttribute = getUnclassifiedRoot(context).get("notifyBitbucket");

        String exported = toYamlString(yourAttribute);

        String expected = toStringFromYamlFile(this, "configuration-as-code-expected.yml");

        assertThat(exported, is(expected));
    }
}
