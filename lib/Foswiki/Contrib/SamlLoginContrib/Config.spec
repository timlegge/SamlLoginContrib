# ---+ Security and Authentication
# ---++ Saml
# This is the configuration used by <b>SamlLoginContrib</b>
# <p>
# To use a Saml server for authentication you have to use the PasswordManager
# <b>none</b>.
#

# ---+++ Connection Settings
# **BOOLEAN LABEL="Enable Debugging"**
# Enable debug mode (to print errors)
$Foswiki::cfg{Saml}{Debug} = 1;

# ---+++ Identity Provider Settings
# **STRING LABEL="IDP Metadata URI"**
# Identity Provider (IdP) metadata file location (must be a URI).
# ACS URL Location where the from the IdP will be returned.
$Foswiki::cfg{Saml}{metadata} = 'http://localhost/metadata.xml';

# **STRING LABEL="Identity Provider CA Cert File"**
# Specify the CA Certificate as a file location.
# Identity Provider CA Certificate
$Foswiki::cfg{Saml}{cacert} = '/var/www/foswiki/saml/cacert.pem';

# **BOOLEAN LABEL="Force Lower Case Logout Response"**
# Some Identity Providers use non-standard lowercase escape codes
# in the URL response.  This is a Net::SAML2 hack to force the uri
# of the response to lowercase (required for Azure)
$Foswiki::cfg{Saml}{sls_force_lcase_url_encoding} = '0';

# **BOOLEAN LABEL="Double Encoded Logout Response"**
# Some Identity Providers respond with double-encoded escape codes
# in the URL of the logout response.  This is a Net::SAML2 hack to
# decode the response twice (required for PingIdentity)
$Foswiki::cfg{Saml}{sls_double_encoded_response} = '0';

# ---+++ Service Provider (Foswiki) Settings
# **STRING LABEL="Service Provider Entity ID (Issuer)"**
# Identifier of the Service Provide (SP) entity (must be a URI).
# Foswiki is the Service Provider as it provides the Service
# Local Copy of Metadata from Identity Provider
$Foswiki::cfg{Saml}{issuer} = 'https://foswiki.local';

# **STRING LABEL="Service Provider Name"**
# Service Provider (Application) name
$Foswiki::cfg{Saml}{provider_name} = 'Foswiki';

# **STRING LABEL="Request Signing Certificate File"**
# Specify the request signing certificate file location.
# Service Provider Signing Certificate File
$Foswiki::cfg{Saml}{sp_signing_cert} = '/var/www/foswiki/saml/sign.pem';

# **STRING LABEL="Request Signing Key File"**
# Specify the private key file location.
# Service Provider Signing Private Key File
$Foswiki::cfg{Saml}{sp_signing_key} = '/var/www/foswiki/saml/sign.key';

# ---+++ Attribute Mapping Settings
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

# **STRING LABEL="Form field to match"**
# Specifies the form field to use for E-Mail address matching.
# By default, if reserving of WikiNames is enabled, the form field to
# match is the 'EMail' field. If this field has a different name in
# your form, you can provide the name here.
$Foswiki::cfg{Saml}{UserFormMatchField} = 'Email';

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

# **STRING LABEL="Forbidden Wikinames"**
# A comma-separated list of WikiNames that should never be given out by this LoginManager.
# If a user authenticates whose ID token would produce one of the WikiNames on this list, the
# user's WikiName will be 'WikiGuest'.
# WikiNames ending in ...Group are automatically rejected, so you don't need to list them here.
$Foswiki::cfg{Saml}{ForbiddenWikinames} = 'AdminUser,ProjectContributor,RegistrationAgent';

# ---+++ Metadata Settings

# **BOOLEAN LABEL="Sign Metadata" \
#   FEEDBACK="icon='ui-icon-play'; label='Generate'; \
#             title='Generate a metadata.xml file from the Service \
#                    Provider (SP) settings.';\
#             wizard='SAML2Metadata'; method='generate'" **
$Foswiki::cfg{Saml}{sign_metatdata} = '1';

# **STRING LABEL="Service Provider Organization"**
# Specifies the organization for the Service Provider Application (Foswiki)
# Used only if you are generating metadata.xml automatically
$Foswiki::cfg{Saml}{org_name} = 'Foswiki';

# **STRING LABEL="Organization Display Name"**
# Specifies the organization name to display for the Service Provider
# Application (Foswiki). Used only if you are generating metadata.xml
$Foswiki::cfg{Saml}{org_display_name} = 'Foswiki Organization';

# **STRING LABEL="Service Provider URL"**
# Specifies a URL for the Identity Provider to use as the main URL for the
# Foswiki INstallation. Used only if you are generating metadata.xml automatically
$Foswiki::cfg{Saml}{url} = 'https://localhost';

# **STRING LABEL="Error URL" EXPERT**
# Specifies a URL for the Identity Provider to use in the case of an error.
# Used only if you are generating metadata.xml automatically
$Foswiki::cfg{Saml}{error_url} = '/bin/login?saml=error';

# **STRING LABEL="Single Logout SOAP URL" EXPERT**
# Specifies a URL for the Identity Provider to use as the SOAP
# Single Logout end point. Used only if you are generating
# metadata.xml automatically
$Foswiki::cfg{Saml}{slo_url_soap} = '/bin/login?saml=slo_soap';

# **STRING LABEL="Single Logout Redirect URL" EXPERT**
# Specifies a URL for the Identity Provider to use as the Redirect
# Single Logout end point. Used only if you are generating
# metadata.xml automatically
$Foswiki::cfg{Saml}{slo_url_redirect} = '/bin/login?saml=slo_redirect';

# **STRING LABEL="Single Logout POST URL" EXPERT**
# Specifies a URL for the Identity Provider to use as the POST
# Single Logout end point. Used only if you are generating
# metadata.xml automatically
$Foswiki::cfg{Saml}{slo_url_post} = '/bin/login?saml=slo_post';

# **STRING LABEL="Authentication Consumer Service (ACS) POST URL" EXPERT**
# Specifies a URL for the Identity Provider to use as the POST
# ACS end point. Used only if you are generating metadata.xml automatically
$Foswiki::cfg{Saml}{acs_url_post} = '/bin/login?saml=acs';

1;
