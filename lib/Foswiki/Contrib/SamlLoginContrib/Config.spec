# ---+ Security and Authentication
# ---++ Saml 
# This is the configuration used by <b>SamlLoginContrib</b>
# <p>
# To use a Saml server for authentication you have to use the PasswordManager
# <b>none</b>.
#

# ---+++ Connection Settings
# **BOOLEAN**
# Enable debug mode (to print errors) 
$Foswiki::cfg{Saml}{Debug} = 1;

# ---+++ Certificates and Metadata a Strings
# **BOOLEAN**
# Didabling this will allo you to use files on the webserver to metadata and certificate files.
$Foswiki::cfg{Saml}{certs_as_string} = 1;

# **STRING**  
# Identity Provider (IdP) metadata file location (must be a URI).
# Local Copy of Metadata from Identity Provider
$Foswiki::cfg{Saml}{metadata} = 'http://localhost/metadata.xml';

# **XML**
# Identity Provider (IdP) metadata xml (must be valid XML).
# Metadata from Identity Provider as a string
$Foswiki::cfg{Saml}{metadata_string} = '';

# **STRING**
# ACS URL Location where the from the IdP will be returned.
$Foswiki::cfg{Saml}{issuer} = 'https://foswiki.local';

# **STRING**
# Service Provider (Application) name
# Bug in Net::SAML2 prevents this from being sent
$Foswiki::cfg{Saml}{provider_name} = 'Foswiki';

# **STRING LABEL="Request Signing Certificate File"**
# Specify the request signing certificate file location.
# Service Provider Signing Certificate File
$Foswiki::cfg{Saml}{sp_signing_cert} = '/var/www/foswiki/saml/sign.pem';     

# **CERT LABEL="Request Signing Certificate (Base64)"**
# Specify the certificate instead of the file location.
# Service Provider Signing Certificate as Base 64 String
$Foswiki::cfg{Saml}{sp_signing_cert_string} = '';

# **STRING LABEL="Request Signing Key File"**
# Specify the private key file location.
# Service Provider Signing Private Key File
$Foswiki::cfg{Saml}{sp_signing_key} = '/var/www/foswiki/saml/sign.key';     

# **CERT LABEL="Request Signing Key (Base64)"**
# Specify the private key instead of the file location.
# Service Provider Signing Private Key as Base 64 String
$Foswiki::cfg{Saml}{sp_signing_key_string} = '';

# **STRING LABEL="Identity Provider CA Cert File"**
# Specify the CA Certificate as a file location.
# Identity Provider CA Certificate
$Foswiki::cfg{Saml}{cacert} = '/var/www/foswiki/saml/cacert.pem';

# **CERT LABEL="Identity Provider CA Cert (Base64)"**
# Specify the CA Certificate instead of the file location.
# Identity Provider CA Certificate as Base 64 String
$Foswiki::cfg{Saml}{cacert_string} = '';

# **STRING LABEL="WikiName Attribute"**
# Comma-separated attributes which should make up the WikiName.
# The default should give good results, but depending on the provider, you might want
# to experiment with other claims, such as the 'name' claim.
$Foswiki::cfg{Saml}{WikiNameAttributes} = 'fname,lname';

# **STRING LABEL="Email Attribute"**
# Attribute which should make up the Email Address.
# The default should give good results, but depending on the provider, you might want
# to experiment with other claims, such as the 'emailaddress' claim.
$Foswiki::cfg{Saml}{EmailAttributes} = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress';

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

