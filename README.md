# SamlLoginContrib
Foswiki login manager via Saml

Code provides a replacement for Foswiki::LoginManager::TemplateLogin to provide 
authenticating users via Saml.

Requires Net::SAML2. Unfortunately the version in CPAN has issues and does not currently 
have an active maintainer so I will be adding the required instructions and patches to
the Docker image at https://github.com/timlegge/docker-foswiki

Net::SAML2 does have a fair number of active users and contributors on github and there
are indications that there will be an official maintainer soon. 

This a currently a very rough implementation base on foswiki/OpenIDLoginContrib 
which made this work a lot easier.  Any bugs in the code are mine and not the author of 
OpenIDLoginContrib (Pascal Schupplili)

Currently it works with Google's SAML apps configuration in Google Apps GSuite and Microsoft Office 365 SAML

# Done
  1. Investigate whether the Net::SAML2 code is vulnerable to XML Comments
     authentication bypass.  Fix Net::SAML2 and mitigate in this Contrib.  
     *Mitigated* in latest https://github.com/timlegge/perl-Net-SAML2
  1. Review the code for bugs and obvious issues
  1. Retest and include one of the GitHub Forks of Net::SAML2 that works correctly
     in the Docker Image above
     *Done* https://github.com/timlegge/docker-foswiki and https://cloud.docker.com/repository/docker/timlegge/docker-foswiki     1. Review the Config.spec and ensure that the correct configurations are included

# ToDo
  1. Add ability to specify nameid in the FoswikiConfig
  Can't actually remember whay I meant here...
