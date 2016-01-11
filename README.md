# Bitbucket Notify Plugin for Jenkins

This Jenkins plugin notifies Bitbucket (Cloud or Server, also known as Stash before) with build result status. 
Failed or successful builds will show up as little icons in the Bitbucket web interface in commit logs. 
Clicking on such an icon will take the user to the specific build.

## Requirements

Compatible bitbucket server:
* **[Stash Server][] 2.1** or newer.
* **[Bitbucket Server][] 4.0** or newer. 
* **[Bitbucket Cloud][]**

Jenkins instance:
* **Jenkins 1.502** or newer

Jenkins plugins:
* **[TokenMacro Plugin](https://wiki.jenkins-ci.org/display/JENKINS/Token+Macro+Plugin) ~1.11**
* **[Credentials Plugin](https://wiki.jenkins-ci.org/display/JENKINS/Credentials+Plugin) ~1.22**

## Usage

1. Configure Stash\Bitbucket Server\Bitbucket Cloud instances on Jenkins Global Configuration page
2. Configure 

That's it. If you have configured everything correctly, Jenkins will notify
your Stash instance of subsequent builds. The result is illustrated on
Atlassians [Stash Build Integration][] wiki page.

### Note on credentials

Currently Stash Build Notifier Plugin accepts only raw plaintext credentials as it work over HTTP REST API of stash

## Under the hood

### For hosted Bitbucket\Stash installation 
This plugin uses the Atlassian [Stash Build REST API][] which was introduced with Stash 2.1.

### For Bitbucket cloud

## Maintainers

* Pavel Batanov ([GitHub](https://github.com/scaytrase))

## License

[Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0.html)

[Stash]: www.atlassian.com/software/stash
[Stash Build Integration]: https://developer.atlassian.com/stash/docs/latest/how-tos/updating-build-status-for-commits.html
[Stash Build REST API]: https://developer.atlassian.com/static/rest/stash/latest/stash-build-integration-rest.html

