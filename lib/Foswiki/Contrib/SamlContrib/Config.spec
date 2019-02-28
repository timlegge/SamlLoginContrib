# ---+ Security and Authentication
# ---++ Saml 
# This is the configuration used by <b>SamlLoginContrib</b>
# <p>
# To use a Saml server for authentication you have to use the PasswordManager
# <b>none</b>.
#

# ---+++ Connection Settings
# **BOOLEAN**
# Reject messages if the SAML standard is not strictly followed or not signed or encrypted if required.
$Foswiki::cfg{Saml}{Strict} = 1;

# **BOOLEAN**
# Enable debug mode (to print errors) 
$Foswiki::cfg{Saml}{Debug} = 1;

# **STRING**  
# Identifier of the Service Provide (SP) entity (must be a URI).
# Foswiki is the Service Provider as it provides the Service
# Local Copy of Metadata from Identity Provider
$Foswiki::cfg{Saml}{metadata} = 'http://localhost/metadata.xml';

# **STRING**
# ACS URL Location where the from the IdP will be returned.
$Foswiki::cfg{Saml}{issuer} = 'https://foswiki.local';

# **STRING**
# Service Provider (Application) name
# Bug in Net::SAML2 prevents this from being sent
$Foswiki::cfg{Saml}{provider_name} = 'Foswiki';

# **STRING**
# Specify the certificate instead of using certs directory.
# Service Provider Signing Certificate
$Foswiki::cfg{Saml}{sp_signing_cert} = '/var/www/foswiki/saml/sign.pem';     

# **STRING**
# Specify the private key instead of using the certs directory.
# Service Provider Signing Key
$Foswiki::cfg{Saml}{sp_signing_key} = '/var/www/foswiki/saml/sign.key';     

# **STRING**
# Instead of use the whole x509cert you can use a fingerprint in order to validate a SAMLResponse.
# The CA Cert for the Identity Providers Certificate
$Foswiki::cfg{Saml}{cacert} = '/var/www/foswiki/saml/cacert.pem';

# **STRING LABEL="WikiName Claims"**
# Comma-separated attributes which should make up the WikiName.
# The default should give good results, but depending on the provider, you might want
# to experiment with other claims, such as the 'name' claim.
$Foswiki::cfg{Saml}{WikiNameAttributes} = 'fname,lname';

# **STRING**
# The Groups to assign to the user upon creation via SAML
$Foswiki::cfg{Saml}{DefaultGroupMemberships} = 'WikiUsers';

# **BOOLEAN LABEL="Reserve WikiNames"**
# Enable this to pre-assign WikiNames to specific people.
# You can make sure that a WikiName will be assigned to a specific user by
# creating a User topic (with the given WikiName) and populating it's EMail
# form field value with the e-mail address of the user. When a user which
# would ordinarily be mapped to the given WikiName authenticates, the e-mail
# claim in his ID token is checked against the form field value and if they
# don't match, the WikiName isn't given out to the user.
# (Don't rely solely on this for security! It isn't foolproof, as not
# every identity provider verifies control over e-mail addresses)
$Foswiki::cfg{Saml}{UserFormMatch} = 0;

# **STRING LABEL="Form field to match"**
# Specifies the form field to use for E-Mail address matching.
# By default, if reserving of WikiNames is enabled, the form field to
# match is the 'EMail' field. If this field has a different name in
# your form, you can provide the name here.
$Foswiki::cfg{Saml}{UserFormMatchField} = 'Email';

# **STRING LABEL="Forbidden Wikinames"**
# A comma-separated list of WikiNames that should never be given out by this LoginManager.
# If a user authenticates whose ID token would produce one of the WikiNames on this list, the
# user's WikiName will be 'WikiGuest'.
# WikiNames ending in ...Group are automatically rejected, so you don't need to list them here.
$Foswiki::cfg{Saml}{ForbiddenWikinames} = 'AdminUser,ProjectContributor,RegistrationAgent';

1;
