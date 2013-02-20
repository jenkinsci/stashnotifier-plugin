Stash Build Notifier Plugin for Jenkins
=======================================

This Jenkins plugin notifies Stash of build results. Failed or
successful builds will show up as little icons in the Stash web 
interface in commit logs. Clicking on such an icon will take the 
user to the specific build.

Requirements
============

* **[Stash][] 2.1** or newer. This plugin uses the Atlassian 
[Stash Build status REST API][] which was introduced with Stash 2.1. 
* *Jenkins 1.466** or newer

Usage
=====

Use the Stash Notifier by adding it as a _Post Step_ in your Jenkins build job 
configuration. 

1. In your Jenkins job configuration, click on *Add post-build step* and select
*Notify Stash Instance*
2. Enter the Stash base URL, e. g. <tt>http://localhost:7990</tt> or 
<tt>http://my.company/stash</tt>. If in doubt, go to your local Stash 
server and check the URL in the browser. The URL 
<tt>http://georg@localhost:7991/projects</tt> reveals the
server base URL, which is <tt>http://localhost:7991</tt>. 
2. Enter the Stash user name which is used to authenticate the plugin with
the Stash build API.
3. Enter the Stash users password.

That's it. If you have configured everything correctly, Jenkins will notify
your Stash instance of subsequent builds. The result is illustrated on
Atlassians [Stash Build Integration][] wiki page.

Authors
=======

Georg Gruetter ([Twitter](https://twitter.com/bumbleGee) [GitHub](https://github.com/gruetter))

License
=======

[Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0.html)



[Stash]: www.atlassian.com/software/stash
[Stash Build Integration]: https://developer.atlassian.com/stash/docs/latest/how-tos/updating-build-status-for-commits.html
[Stash Build REST API]: https://developer.atlassian.com/static/rest/stash/latest/stash-build-integration-rest.html
