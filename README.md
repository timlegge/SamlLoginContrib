# SamlLoginContrib
Foswiki login manager via Saml

Code provides a replacement for Foswiki::LoginManager::TemplateLogin which in addition
to serving the role of TemplateLogin is also capable of authenticating users via
Saml.

Requires Net::SAML2. Unfortunately the version in CPAN has issues and does not currently 
have an active maintainer so I will be adding the required instructions and patches to
the Docker image at https://github.com/timlegge/docker-foswiki/tree/saml_support

Net::SAML2 does have a fair number of active users and contributors on github

This a currently a very rough implementation base on foswiki/OpenIDLoginContrib 
which made this work a lot easier.  Any bugs in the code are mine and not the author of 
OpenIDLoginContrib (Pascal Schupplili)

Currently it works with Google's SAML apps configuration in Google Apps GSuite
