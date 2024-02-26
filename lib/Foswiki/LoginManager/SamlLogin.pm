# Module of Foswiki - The Free and Open Source Wiki, http://foswiki.org/
#
# Copyright (C) 2019-2022 by Timothy Legge timlegge@gmail.com
# Based on foswiki/OpenIDLoginContrib
# Copyright (C) 2016 by Pascal Schuppli pascal.schuppli@gbsl.ch
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version. For
# more details read LICENSE in the root of this distribution.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
package Foswiki::LoginManager::SamlLogin;

=begin TML

---+ Foswiki::LoginManager::SamlLogin

This provides a LoginManager which can authenticate using
Saml, while still providing access to the underlying
TemplateLogin manager.

=cut

use strict;
use warnings;
use Net::SAML2 0.78;
use Net::SAML2::XML::Sig;
use URN::OASIS::SAML2 qw(:bindings :urn);
use MIME::Base64 qw/ decode_base64 /;
use Foswiki;
use Foswiki::LoginManager::TemplateLogin ();
use Data::Dumper;

@Foswiki::LoginManager::SamlLogin::ISA = qw( Foswiki::LoginManager::TemplateLogin );

=begin TML

---++ ClassMethod new($session)

Construct the <nop> object

=cut

sub new {
  my ($class, $session) = @_;
  my $this = bless($class->SUPER::new($session), $class);
  undef $this->{Saml}{debug};
  undef $this->{Saml}{metadata};
  undef $this->{Saml}{cacert};
  undef $this->{Saml}{sp_signing_key};
  undef $this->{Saml}{sp_signing_cert};
  undef $this->{Saml}{issuer};
  undef $this->{Saml}{provider_name};
  undef $this->{Saml}{sls_force_lcase_url_encoding};
  undef $this->{Saml}{sls_double_encoded_response};
  undef $this->{Saml}{SupportSLO};
  undef $this->{Saml}{AttributeMap};
  undef $this->{Saml}{Debug};
  undef $this->{Saml}{EmailAttributes};
  undef $this->{Saml}{ForbiddenWikinames};
  undef $this->{Saml}{UserFormMatch};
  undef $this->{Saml}{UserFormMatchField};
  undef $this->{Saml}{WikiNameAttributes};
  undef $this->{Saml}{acs_url_artifact};
  undef $this->{Saml}{acs_url_post};
  undef $this->{Saml}{error_url};
  undef $this->{Saml}{org_contact};
  undef $this->{Saml}{org_display_name};
  undef $this->{Saml}{org_name};
  undef $this->{Saml}{sign_metatdata};
  undef $this->{Saml}{slo_url_post};
  undef $this->{Saml}{slo_url_redirect};
  undef $this->{Saml}{slo_url_soap};
  undef $this->{Saml}{url};

  Foswiki::registerTagHandler( 'LOGOUT',           \&_LOGOUT );
  Foswiki::registerTagHandler( 'LOGOUTURL',        \&_LOGOUTURL );

  return $this;
}

=pod
---++ ObjectMethod loadSamlData()
Given a provider key which must reference a key in the Foswiki configuration
under Extensions->Saml, loads relevant provider information into object
properties.
=cut
sub loadSamlData {
    my $this = shift;

    #
    # TODO: We should cache this. On sites with heavy traffic, this adds needless delays, especially since
    # we need to load it twice for each login
    $this->{Saml}{debug}              = $Foswiki::cfg{Saml}{Debug};
    $this->{Saml}{metadata}           = $Foswiki::cfg{Saml}{metadata};
    $this->{Saml}{cacert}             = $Foswiki::cfg{Saml}{cacert};
    $this->{Saml}{sp_signing_key}     = $Foswiki::cfg{Saml}{sp_signing_key};
    $this->{Saml}{sp_signing_cert}    = $Foswiki::cfg{Saml}{sp_signing_cert};
    $this->{Saml}{issuer}             = $Foswiki::cfg{Saml}{issuer};
    $this->{Saml}{provider_name}      = $Foswiki::cfg{Saml}{provider_name};
    $this->{Saml}{sls_force_lcase_url_encoding} = $Foswiki::cfg{Saml}{sls_force_lcase_url_encoding} || '0';
    $this->{Saml}{sls_double_encoded_response}  = $Foswiki::cfg{Saml}{sls_double_encoded_response} || '0';
    $this->{Saml}{SupportSLO}         = $Foswiki::cfg{Saml}{SupportSLO} || '0';

    if ( $this->{Saml}{debug} ) {
        Foswiki::Func::writeDebug("loadSamlData:");
        Foswiki::Func::writeDebug("    Net::SAML2 version $Net::SAML2::VERSION");
        Foswiki::Func::writeDebug("    {Saml}{debug}:           $this->{Saml}{debug}");
        Foswiki::Func::writeDebug("    {Saml}{metadata}:        $this->{Saml}{metadata}");
        Foswiki::Func::writeDebug("    {Saml}{cacert}:          $this->{Saml}{cacert}");
        Foswiki::Func::writeDebug("    {Saml}{sp_signing_key}:  $this->{Saml}{sp_signing_key}");
        Foswiki::Func::writeDebug("    {Saml}{sp_signing_cert}: $this->{Saml}{sp_signing_cert}");
        Foswiki::Func::writeDebug("    {Saml}{issuer}:          $this->{Saml}{issuer}");
        Foswiki::Func::writeDebug("    {Saml}{provider_name}:   $this->{Saml}{provider_name}");
        Foswiki::Func::writeDebug("    {Saml}{sls_force_lcase_url_encoding}:   $this->{Saml}{sls_force_lcase_url_encoding}");
        Foswiki::Func::writeDebug("    {Saml}{sls_double_encoded_response}:   $this->{Saml}{sls_double_encoded_response}");
        Foswiki::Func::writeDebug("    {Saml}{SupportSLO}:   $this->{Saml}{SupportSLO}");
    }
}

sub getAndClearSessionValue {
    my $this = shift;
    my $key = shift;

    my $value = Foswiki::Func::getSessionValue($key);
    Foswiki::Func::clearSessionValue($key);

    return $value;
}

# Pack key request parameters into a single value
# Used for passing meta-information about the request
# through a URL (without requiring passthrough)
sub _packRequest {
    my ( $uri, $method, $action ) = @_;
    return '' unless $uri;
    if ( ref($uri) ) {    # first parameter is a $session
        my $r = $uri->{request};
        $uri    = $r->uri();
        $uri    = Foswiki::urlDecode($uri);
        $method = $r->method() || 'UNDEFINED';
        $action = $r->action();
    }
    return "$method,$action,$uri";
}

=pod
---++ ObjectMethod extractEmail($attributes) -> $email
Given a Saml attributes, tries to find an e-mail claim and returns
it. Currently this is rather dumb; it should be made more intelligent.
=cut
sub extractEmail {
    my $this        = shift;
    my $attributes  = shift;

    my $email = $Foswiki::cfg{Saml}{EmailAttributes};

    return $attributes->{$email}[0] if exists $attributes->{$email};

    return '';
}

=pod
---++ ObjectMethod extractLoginname($nameid) -> $loginname
This extracts a Foswiki loginname from a id token. Which claim
is used as the login name ultimately depends on the attribute configured
in Foswiki::cfg.
=cut
sub extractLoginname {
    my $this    = shift;
    my $nameid  = shift;

    Foswiki::Func::writeDebug(
        "    extractLoginname:") if $this->{Saml}{debug};

    my $login = $nameid;
    # SMELL: This is here to make valid login names out of MS Azure AD
    # subject values. Probably shouldn't be done here, and this explicitly.
    $login =~ s/-/_/g;

    return $login;
}

=pod
---++ ObjectMethod buildWikiName($attributes) => $wikiname
Given the Saml attributes, builds a wikiname from it. Which attributes are used to
build the wikiname ultimately depends on the Foswiki::cfg settings.
If the wikiname that's built ends in ...Group or is contained in
the list of forbidden WikiNames, WikiGuest (or rather, the configured
default WikiName) is returned instead.
=cut
sub buildWikiName {
    my $this = shift;
    my $attributes = shift;

    Foswiki::Func::writeDebug(
        "    buildWikiName:") if $this->{Saml}{debug};

    $this->{wikiname_attrs} = $Foswiki::cfg{Saml}{WikiNameAttributes};

    my $wikiname_attributes = $this->{'wikiname_attrs'};
    my $wikiname = '';

    foreach my $attr (split(/\s*,\s*/, $wikiname_attributes)) {
        $wikiname .= $attributes->{$attr}[0];
    }

    # some minimal normalization
    $wikiname =~ s/\s+//g;

    if ($wikiname =~ m/Group$/) {
        return $Foswiki::cfg{DefaultUserWikiName};
    }

    # Forbidden wikinames get mapped to WikiGuest too
    my @forbidden = split(/\s+,\s+/, $Foswiki::cfg{Saml}{ForbiddenWikinames});
    for my $bignono (@forbidden) {
        if ($wikiname eq $bignono) {
            return $Foswiki::cfg{DefaultUserWikiName};
        }
    }
    return $wikiname;
}

=pod
---++ ObjectMethod matchWikiUser($wikiname, $email) => $wikiname
This checks whether the e-mail address stored in a WikiName topic's
form field matches the $email argument. If it does, then the name
of the topic (e.g. the $wikiname) is returned. If it doesn't,
undef is returned.
The wikiname is also returned when the WikiName topic doesn't exist
or pre-assigning wikinames is disabled in the configuration.
=cut
sub matchWikiUser {
    my $this     = shift;
    my $wikiname = shift;
    my $email    = shift;

    Foswiki::Func::writeDebug(
        "    matchWikiUser:") if $this->{Saml}{debug};

    my $web = $Foswiki::cfg{UsersWebName} || 'Main';

    # If the Wiki User Topic doesn't exist, there is no forseeable conflict,
    # so we return the candidate wikiname unchanged. We also return immediately
    # if User Form Matching is disabled.
    if (!Foswiki::Func::topicExists($web, $wikiname) || !$Foswiki::cfg{Saml}{UserFormMatch}) {
        return $wikiname;
    }

    # otherwise, we see if the e-mail address matches the one in the user topic.
    # if so, we pronounce a match.
    my $fieldname = $Foswiki::cfg{Saml}{UserFormMatchField} || 'Email';
    my $options = {
        type => 'query',
        web => $web,
    };

    my $matches = Foswiki::Func::query(
        "fields[name='$fieldname'].value=~'^\\s*$email\\s*\$'", ["$web.$wikiname"], $options);

    while ($matches->hasNext) {
        my $found = $matches->next;
        my ($dummy, $wikiname) = Foswiki::Func::normalizeWebTopicName('', $found);
        return $wikiname;
    }
    # No match. This means we shouldn't give out the candidate $wikiname.
    return undef;
}

=pod
---++ ObjectMethod _isAlreadyMapped($session, $loginname, $wikiname) => $boolean
This is an internal helper function which tries to determine whether a given loginname
is already mapped to a wikiname or not.
Unfortunately, there doesn't seem to be a "right" way to determine this while staying
inside the constraints of the public API.
=cut
sub _isAlreadyMapped {
    my $this        = shift;
    my $session     = shift;
    my $loginname   = shift;
    my $wikiname    = shift;

    Foswiki::Func::writeDebug(
        "    _isAlreadyMapped:") if $this->{Saml}{debug};

    # Currently, there doesn't seem to be a universal way to check
    # whether a mapping between login name and username is already
    # in place.
    my $is_mapped = 0;
    if ($Foswiki::cfg{Register}{AllowLoginName}) {
        my $aWikiname = Foswiki::Func::userToWikiName($loginname, 1);
        Foswiki::Func::writeDebug(
          "        loginname: $loginname") if $this->{Saml}{debug};
        Foswiki::Func::writeDebug(
          "        aWikiName: $aWikiname") if $this->{Saml}{debug};
        $is_mapped = $aWikiname ne $loginname;
        Foswiki::Func::writeDebug(
          "        is_mapped: ",  $is_mapped ? 'true' : 'false') if $this->{Saml}{debug};
        return $is_mapped;
    } else {
        # It's important to return 0 here so that if mapping is turned
        # off, on-the-spot pre-assignment checking is initiated by mapUser.
        # If this returned 1, we'd never do any checking.
        return 0;
    }
}

=pod
---++ ObjectMethod mapUser($session, $attributes, $nameid) => $cuid
This handles the mapping of a loginname as extracted from the SamlResponse
to a WikiName. We don't keep a mapping ourselves; we simply instruct
the configured UserMapper to create one if it doesn't exist yet. If
the UserMapper doesn't create a permanent mapping, we'll go through
the same motions again when the user authenticates the next time.
Much of the code here is concerned with trying to make sure that
WikiNames which were pre-assigned aren't used in a mapping by
mistake before the actual user authenticates and claims the WikiName.
We also handle duplicate names by increasing a counter to generate
WikiName2, WikiName3, WikiName4 etc.
=cut
sub mapUser {
    my $this         = shift;
    my $session      = shift;
    my $attributes   = shift;
    my $nameid       = shift;

    Foswiki::Func::writeDebug(
          "    mapUser:") if $this->{Saml}{debug};

    my $loginname = undef;
    my $candidate = $this->buildWikiName($attributes);

    Foswiki::Func::writeDebug(
          "        candidate: $candidate") if $this->{Saml}{debug};

    if ($Foswiki::cfg{Register}{AllowLoginName}) {
        $loginname = $this->extractLoginname($nameid);
        Foswiki::Func::writeDebug(
                    "        loginname: $loginname") if $this->{Saml}{debug};
    }
    else {
        # SMELL: Turning off AllowLoginName for Open ID is a really bad idea. Should
        # we complain, or add a warning to the log?
        $loginname = $candidate;
    }

    my $email = lc($this->extractEmail($attributes));

    Foswiki::Func::writeDebug(
          "        email: $email") if $this->{Saml}{debug};

    if (!$this->_isAlreadyMapped($session, $loginname, $candidate)) {
        Foswiki::Func::writeDebug(
            "        Login not mapped") if $this->{Saml}{debug};
        my $wikiname = undef;
        my $orig_candidate = $candidate;
        my $counter = 1;
        # Find an acceptable wikiname. We simply add an increasing number if a name is taken already
        while (!defined($wikiname)) {
            my $users = $session->{users}->findUserByWikiName($candidate);
            if (scalar @$users == 0) {
                $wikiname = $this->matchWikiUser($candidate, $email);
                Foswiki::Func::writeDebug(
                    "            candidate: $candidate produces wikiname: $wikiname")
                        if $this->{Saml}{debug};
                if (defined $wikiname) {
                    my $cuid = $session->{'users'}->addUser($loginname, $wikiname, undef, [$email]);
                    Foswiki::Func::writeDebug(
                        "            cuid: $cuid (email: $email) to wikiname: $wikiname") if $this->{Saml}{debug};
                    return $cuid;
                }
            }
            $counter = $counter + 1;
            $candidate = $orig_candidate . $counter;
        }
    } else {
        # Mapping exists already, so return the canonical user id
        my $cuid = $session->{users}->getCanonicalUserID($loginname);
        Foswiki::Func::writeDebug(
            "            Saml Use preexisting mapping for $loginname") if $this->{Saml}{debug};
        return $cuid;
    }
}
=pod
---++ ObjectMethod redirectToProvider($request_url, $query, $session)

This is called directly by login() and is responsible for building
the redirect url to the Saml provider. It generates the redirect
and sends it back to the user agent.
=cut
sub redirectToProvider {
    my $this        = shift;
    my $request_url = shift;
    my $query       = shift;
    my $session     = shift;

    my $topic       = $session->{topicName};
    my $web         = $session->{webName};
    my $response    = $session->{response};

    Foswiki::Func::writeDebug("redirectToProvider:")
        if $this->{Saml}{ debug };

    if ( $this->{Saml}{ debug } ) {
        Foswiki::Func::writeDebug("    redirectToProvider set session values");
        Foswiki::Func::writeDebug("        topicName: $topic");
        Foswiki::Func::writeDebug("        webName:   $web");
        Foswiki::Func::writeDebug("        redirecting to:   $request_url");
    }

    Foswiki::Func::setSessionValue('saml_web', $web);
    Foswiki::Func::setSessionValue('saml_topic', $topic);

    $response->redirect($request_url);
}

=pod
---++ ObjectMethod samlLogout($saml_response, $query, $session)
This is called directly by login() when login() detects a successful
Logout response from the Saml provider. When we get here, we have SAML
response that needs to be decoded.
=cut

sub samlLogoutResponse
{
    my $this            = shift;
    my $saml_response   = shift;
    my $query           = shift;
    my $session         = shift;
    my $type            = shift;
    my $relaystate      = shift;

    # Store the saml_logoutrequest_id that was set from the original
    # LogoutRequest id
    my $saml_logoutrequest_id = $this->getAndClearSessionValue('saml_logoutrequest_id');

    Foswiki::Func::writeDebug("samlLogoutResponse:")
        if $this->{Saml}{ debug };

    Foswiki::Func::writeDebug(
        "        query method - $type") if $this->{Saml}{ debug };

    my ( $origurl, $origmethod, $origaction ) =
        Foswiki::LoginManager::TemplateLogin::_unpackRequest($relaystate);

    if ( $this->{Saml}{ debug } ) {
        my $text =  "\n        RelayState   : $relaystate\n" .
                    "            origurl    : $origurl\n" .
                    "            origmethod : $origmethod\n" .
                    "            origaction : $origaction";
        Foswiki::Func::writeDebug(
            "$text");
    }

    my $idp = Net::SAML2::IdP->new_from_url(
        url                             => $this->{Saml}{metadata},
        cacert                          => $this->{Saml}{cacert},
        sls_force_lcase_url_encoding    => $this->{Saml}{sls_force_lcase_url_encoding},
        sls_double_encoded_response     => $this->{Saml}{sls_double_encoded_response}
    );

    my $logout;
    if ($type eq 'GET') {
        # LogoutResponse was a HTTP-Redirect - GET
        Foswiki::Func::writeDebug(
            "        LogoutResponse was a $type") if $this->{Saml}{ debug };

        my $redirect = Net::SAML2::Binding::Redirect->new(
            url                             => $idp->slo_url(
                                                'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
            key                             => $this->{Saml}{sp_signing_key},
            cert                            => $idp->{certs}{'signing'},
            param                           => 'SAMLResponse',
            sls_force_lcase_url_encoding    => $this->{Saml}{sls_force_lcase_url_encoding},
            sls_double_encoded_response     => $this->{Saml}{sls_double_encoded_response}
        );

        my $uri = $query->{uri};
        Foswiki::Func::writeDebug(
            "        SAMLResponse URI: - $uri") if $this->{Saml}{ debug };

        my ($response, $relaystate) = $redirect->verify($uri);

        ( $origurl, $origmethod, $origaction ) =
            Foswiki::LoginManager::TemplateLogin::_unpackRequest($relaystate);

        if ( $this->{Saml}{ debug } ) {
            my $text =  "\n        RelayState   : $relaystate\n" .
                        "            origurl    : $origurl\n" .
                        "            origmethod : $origmethod\n" .
                        "            origaction : $origaction";
            Foswiki::Func::writeDebug(
                "$text");
        }

        if ($response) {
            $logout = Net::SAML2::Protocol::LogoutResponse->new_from_xml(
                 xml => $response
            );
            Foswiki::Func::writeDebug(
                "        Logout Response was properly signed: $response") if $this->{Saml}{ debug };
        } else {
            Foswiki::Func::writeDebug(
                "        LogoutResponse verification failed: $response") if $this->{Saml}{ debug };
            return $origurl;
        }

    } else {
        # LogoutResponse was a HTTP-POST - POST
        Foswiki::Func::writeDebug(
            "        LogoutResponse was a $type") if $this->{Saml}{ debug };
        my $post = Net::SAML2::Binding::POST->new(
            cacert => $this->{Saml}{cacert},
        );

        my $xml = $post->handle_response(
            $saml_response,
        );

        Foswiki::Func::writeDebug(
            "        saml_response = " . $xml) if $this->{Saml}{ debug };

        Foswiki::Func::writeDebug(
            "        RelayState = $relaystate") if $this->{Saml}{ debug };

        # The handle_response above checks the cert and cacert if it is defined
        # so if $xml was returned the verification occured properly.
        if (defined($xml)) {
            $logout = Net::SAML2::Protocol::LogoutResponse->new_from_xml(
                        xml => $xml
            );
            Foswiki::Func::writeDebug(
                "        Logout Response was properly signed: $xml") if $this->{Saml}{ debug };
        }
        else {
            # Logout Response was not properly signed
            Foswiki::Func::writeDebug(
                "        Logout Response was not properly signed: $xml") if $this->{Saml}{ debug };
            return $origurl;
        }
    }

    if ($saml_logoutrequest_id ne $logout->{response_to}) {
        my $topic       = $session->{topicName};
        my $web         = $session->{webName};

        throw Foswiki::OopsException( 'samllogincontrib',
                            status => 500,
                            web => $web,
                            topic => $topic,
                            params => [ 'logout', 'InResponseTo Mismatch',
                                        "Request id: $saml_logoutrequest_id",
                                        "InResponseTo $logout->{response_to}",] );

        $session->redirect( $origurl, 1 );
        return $origurl;
    }

    if ($logout->status eq 'urn:oasis:names:tc:SAML:2.0:status:Success') {
        my $sessionindex = $this->getAndClearSessionValue('saml_session_index');

        $this->{_cgisession}->delete();
        $this->{_cgisession}->flush();
        $this->{_cgisession} = undef;
        $this->_delSessionCookieFromResponse();

        $session->{request}->delete('logout');

        if ( $this->{Saml}{ debug } ) {
            my $text =  "\n        RelayState   : $relaystate\n" .
                        "            origurl    : $origurl\n" .
                        "            origmethod : $origmethod\n" .
                        "            origaction : $origaction";
            Foswiki::Func::writeDebug(
                "$text");
            Foswiki::Func::writeDebug(
                "        Original LogoutRequest id - $saml_logoutrequest_id") if $this->{Saml}{ debug };
            Foswiki::Func::writeDebug(
                "        Logout InResponseTo - $logout->{response_to}") if $this->{Saml}{ debug };
            Foswiki::Func::writeDebug(
                "        Logout Success Status - $logout->{issuer}") if $this->{Saml}{ debug };
        }
    }
    else {
        my $topic       = $session->{topicName};
        my $web         = $session->{webName};
        throw Foswiki::OopsException( 'samllogincontrib',
                    status => 500,
                    web => $web,
                    topic => $topic,
                    params => [ 'logout', 'Logout Failure',
                                "Status: $logout->{status}",
                                "Additional Info: $logout->{substatus}",] );

        Foswiki::Func::writeDebug(
            "        Logout Failed Status") if $this->{Saml}{ debug };
        $session->redirect( $origurl, 1 );
        return $origurl;
    }
    return $origurl;
}

=pod
---++ ObjectMethod samlCallback($saml_response, $query, $session)
This is called directly by login() when login() detects a successful
callback from the Saml provider. When we get here, we have SAML
response that needs to be  and decoder for user information.
=cut
sub samlCallback {
    my $this            = shift;
    my $saml_response   = shift;
    my $query           = shift;
    my $session         = shift;
    my $relaystate      = shift;

    my $origin  = $this->getAndClearSessionValue('saml_origin');
    my $web     = $this->getAndClearSessionValue('saml_web') || '';
    my $topic   = $this->getAndClearSessionValue('saml_topic') || '';

    Foswiki::Func::writeDebug(
        "    samlCallback") if $this->{Saml}{ debug };

    # Store now as is it used in several places in the code below
    my ( $origurl, $origmethod, $origaction ) =
        Foswiki::LoginManager::TemplateLogin::_unpackRequest($relaystate);

    # A GET request is not supported for Assertions so is
    # really only going to be a LogoutResponse
    if ($query->{method} eq 'GET') {
        Foswiki::Func::writeDebug(
            "        HTTP-GET") if $this->{Saml}{ debug };
        Foswiki::Func::writeDebug("    SAML Logout received") if $this->{Saml}{ debug };
        $origurl = $this->samlLogoutResponse($saml_response, $query, $session, $query->{method}, $relaystate);
        # Don't show the SAMLReponse in the URL
        #$query->delete('SAMLResponse');
        $query->deleteAll;

        return;
    }
    else {
        # This is a the ACS handler to handle the SAML2 Response and Assertion
        Foswiki::Func::writeDebug(
            "        HTTP-POST") if $this->{Saml}{ debug };

        #  Create the POST binding object to get the details from the SALMResponse'
        my $post = Net::SAML2::Binding::POST->new(cacert => $this->{Saml}{cacert});

        Foswiki::Func::writeDebug("        Net::SAML2::Binding::POST created") if $this->{Saml}{ debug };

        # Send the SAMLResponse to the Binding for the POST
        # The return has the CA certificate Subject and verified if correct
        my $xml = $post->handle_response(
                $saml_response
        );

        Foswiki::Func::writeDebug(
            "        SAMLResponse handle_response $xml") if $this->{Saml}{ debug };
        if ($xml) {
            Foswiki::Func::writeDebug(
            "        SAMLResponse handled successfully by POST") if $this->{Saml}{ debug };

            my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
                xml         => $xml,
                key_file    => $this->{Saml}{sp_signing_key},
                cacert      => $this->{Saml}{cacert},
            );

            if ( $this->{Saml}{ debug } ){
                Foswiki::Func::writeDebug("        Assertion extracted from SAMLResponse XML");
                Foswiki::Func::writeDebug("            InResponseTo: $assertion->{ in_response_to }");
                Foswiki::Func::writeDebug("            SessionIndex: $assertion->{ session }");
            }
=pod
            Verify that the response was related to the request
            the issuer and the id from the Saml Authnreq must be sent to the Assertion->valid()
            probably a better way to track the id/inresponseto
=cut
            my $issuer          = $this->{Saml}{ issuer };
            my $saml_request_id = $this->getAndClearSessionValue('saml_request_id');

            # $assertion->valid() checks the dates and the audience
            my $valid = $assertion->valid($issuer, $saml_request_id);

            if (!$valid) {
                throw Foswiki::OopsException( 'samllogincontrib',
                            status => 500,
                            web => $web,
                            topic => $topic,
                            params => [ 'login', 'InResponseTo Mismatch',
                                        "Request id: $saml_request_id",
                                        "InResponseTo $assertion->{in_response_to}",] );

                # Always print this in debug as the chances of this occuring is rare
                Foswiki::Func::writeDebug("        SAML assertion is invalid");
                Foswiki::Func::writeDebug("            Issuer:       $issuer");
                Foswiki::Func::writeDebug("            InResponseTo: $saml_request_id");
                Foswiki::Func::writeDebug("            SessionIndex: $assertion->{ session }");
                Foswiki::Func::writeDebug("            NotBefore:    $assertion->{ not_before }");
                Foswiki::Func::writeDebug("            NotAfter:     $assertion->{ not_after }");

                $query->method($origmethod);
                Foswiki::Func::writeDebug("            Redirect: $origurl") if $this->{Saml}{ debug };
                $session->redirect( $origurl, 1 );
                return;
            }
            else {
                # The SAML Assertion is valid
                if ( $this->{Saml}{debug} == 1 ) {
                    # output the attributes and values that are available in the response
                    keys %{$assertion->attributes};
                    Foswiki::Func::writeDebug(
                        "            Assertion Attributes from SAMLResponse");

                    while(my($k, $v) = each %{$assertion->attributes}) {
                        my $val = %$v[0];
                        Foswiki::Func::writeDebug("                $k: $val");
                    }
                }

                Foswiki::Func::writeDebug("            Assertion NameID $assertion->{nameid}")
                    if defined $assertion->{nameid} && $this->{Saml}{ debug };

                my $cuid = $this->mapUser($session, $assertion->attributes, $assertion->nameid);

                # SMELL: This isn't part of the public API!
                # But Foswiki::Func doesn't provide login name lookup and
                # wikiname lookup doesn't work yet at that stage (yields the loginname, ironically...)
                my $wikiname = $session->{users}->getWikiName($cuid);
                my $loginName = $session->{users}->getLoginName($cuid);

                my $sessionindex = $this->getAndClearSessionValue('saml_session_index');
                Foswiki::Func::setSessionValue('saml_session_index', $assertion->{ session });

                Foswiki::Func::writeDebug("    Login Name: $loginName") if $this->{Saml}{ debug };

                $this->userLoggedIn($loginName);
                #    $session->inContext('authenticated');
                $session->logger->log({
                    level    => 'info',
                    action   => 'login',
                    webTopic => $web . '.' . $topic,
                    extra    => "AUTHENTICATION SUCCESS - $loginName ($wikiname) - "
                });

                if ( !$origurl || $origurl eq $query->url() ) {
                    $origurl = $session->getScriptUrl( 0, 'view', $web, $topic );
                }
                else {
                    # Unpack params encoded in the origurl and restore them
                    # to the query. If they were left in the query string they
                    # would be lost if we redirect with passthrough.
                    # First extract the params, ignoring any trailing fragment.
                    if ( $origurl =~ s/\?([^#]*)// ) {
                        foreach my $pair ( split( /[&;]/, $1 ) ) {
                            if ( $pair =~ m/(.*?)=(.*)/ ) {
                                # SMELL: Removed TAINT on $2 because couldn't
                                # figure out where it was defined
                                $query->param( $1, $2 );
                            }
                        }
                    }

                    # Restore the action too
                    $query->action($origaction) if $origaction;
                }

                if (
                    $this->{session}->topicExists(
                        $Foswiki::cfg{UsersWebName},
                        $wikiname
                    )
                )
                {
                    Foswiki::Func::writeDebug("    UserTopic Exists update form for: $Foswiki::cfg{UsersWebName}.$wikiname") if $this->{Saml}{ debug };
                    $session->{'users'}->setEmails($cuid, $assertion->attributes->{'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'}[0]);
                    $this->setUserFields($cuid, $assertion->attributes);
                } else {
                    Foswiki::Func::writeDebug("    UserTopic does not exists for: $Foswiki::cfg{UsersWebName}.$wikiname") if $this->{Saml}{ debug };
                }
                # Restore the method used on origUrl so if it was a GET, we
                # get another GET.
                $query->method($origmethod);
                Foswiki::Func::writeDebug("            Redirect: $origurl") if $this->{Saml}{ debug };
                $session->redirect( $origurl, 1 );
                return;
            }
        }
    }
    # Failed POST handle_response
    # Send user back to original page
    $query->method($origmethod);
    $session->redirect( $origurl, 1 );
    return;
}

=begin TML

---++ ObjectMethod _LOGOUTURL ($thisl)


=cut

sub _LOGOUTURL {
    my ( $session, $params, $topic, $web ) = @_;

    my $url = $session->getScriptUrl( 0, 'login', undef, undef,
        'saml' => 'logout') . '&foswiki_origin=' . _packRequest($session);

    return $url;

}

sub _LOGOUT {
    my ( $session, $params, $topic, $web ) = @_;

    Foswiki::Func::writeDebug("_LOGOUT:")
        if $session->{Saml}{ debug };

    return '' unless $session->inContext('authenticated');

    my $url = _LOGOUTURL(@_);
    if ($url) {
        my $text = $session->templates->expandTemplate('LOG_OUT');
        return CGI::a( { href => $url }, $text );
    }
    return '';
}

=begin TML

---++ ObjectMethod loginUrl () -> $loginUrl

Overrides LoginManager. Content of a login link.

=cut

sub loginUrl {
    my $this    = shift;
    my $session = $this->{session};
    my $topic   = $session->{topicName};
    my $web     = $session->{webName};

    Foswiki::Func::writeDebug("loginUrl:")
        if $this->{Saml}{ debug };

    return $session->getScriptUrl( 0, 'login', undef, undef,
        foswiki_origin => _packRequest($session) );
}

=begin TML
---++ ObjectMethod logoutUrl ()

Provides a NatSkinPlugin supported logoutUrl
to return a URL for the logout action

=cut

sub logoutUrl {
    my $this    = shift;
    my $session = $this->{session};

    return $session->getScriptUrl( 0, 'login', undef, undef,
        saml => 'logout', foswiki_origin => _packRequest($session) );

}

=begin TML

---++ ObjectMethod _logoutUrl () -> $_logoutUrl

Internal function to generate the SAML logout URL.  The user's logout
action calls the bin/login?saml=logout generated by logoutUrl and the
login script calls this function to generate the SAML LogoutRequest URL

=cut

sub _logoutUrl {
    my $this            = shift;
    my $foswiki_origin  = shift;

    Foswiki::Func::writeDebug("_logoutUrl:")
        if $this->{Saml}{ debug };

    my $session = $this->{session};

    $this->loadSamlData();

    if ( ! defined $this->{Saml}{SupportSLO} || ! $this->{Saml}{SupportSLO} ) {
        Foswiki::Func::writeDebug("    support for SAML Logout is disabled _LOGOUTURL")
            if $this->{Saml}{ debug };
        return $session->getScriptUrl(
            0, 'view',
            $session->{prefs}->getPreference('BASEWEB'),
            $session->{prefs}->getPreference('BASETOPIC'),
            'logout' => 1
        );
    }

    my $idp = Net::SAML2::IdP->new_from_url(
        url     => $this->{Saml}{metadata},
        cacert  => $this->{Saml}{cacert},
        sls_force_lcase_url_encoding => $this->{Saml}{sls_force_lcase_url_encoding},
        sls_double_encoded_response => $this->{Saml}{sls_double_encoded_response}
    );

    if ( (!defined $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect')) &&
         (!defined $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST')) ) {
        Foswiki::Func::writeDebug("    no slo_url defined in Identity provider metadata")
            if $this->{Saml}{ debug };

        return $session->getScriptUrl(
            0, 'view',
            $session->{prefs}->getPreference('BASEWEB'),
            $session->{prefs}->getPreference('BASETOPIC'),
            'logout' => 1
        );
    }

    my $sessionindex = $this->getSessionValue('saml_session_index');
    Foswiki::Func::writeDebug("    SessionIndex: $sessionindex") if $this->{Saml}{ debug };

    if ( $sessionindex eq '' ) {
        Foswiki::Func::writeDebug("    SessionIndex is not set defaulting to LoginManager _LOGOUTURL")
            if $this->{Saml}{ debug };
        return $session->getScriptUrl(
            0, 'view',
            $session->{prefs}->getPreference('BASEWEB'),
            $session->{prefs}->getPreference('BASETOPIC'),
            'logout' => 1
        );
    }

    $idp = Net::SAML2::IdP->new_from_url(
        url     => $this->{Saml}{ metadata},
        cacert  => $this->{Saml}{ cacert },
    );

    Foswiki::Func::writeDebug("    user:", $session->{users}->getLoginName($session->{user}))
        if $this->{Saml}{ debug };

    my $logoutrequest = Net::SAML2::Protocol::LogoutRequest->new(
        issuer        => $this->{Saml}{ issuer },
        nameid_format => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        destination   => $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        nameid      => $session->{users}->getLoginName($session->{user}),
        session     => $sessionindex,
    );

    my $logoutreq = $logoutrequest->as_xml;

    # Store the request's id for later verification
    Foswiki::Func::setSessionValue('saml_logoutrequest_id', $logoutrequest->{id});

    Foswiki::Func::writeDebug("    Saml: logouturl LogoutRequest ID: ", $logoutrequest->{id}) if $this->{Saml}{ debug };
    Foswiki::Func::writeDebug("    Saml: logouturl logoutreq: ", $logoutreq) if $this->{Saml}{ debug };
    my $redirect = Net::SAML2::Binding::Redirect->new(
              key => $this->{Saml}{ sp_signing_key },
              cert => $this->{Saml}{ sp_signing_cert },
              destination   => $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
              param => 'SAMLRequest',
              url   => $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
    );

    Foswiki::Func::writeDebug("    $foswiki_origin") if $this->{Saml}{ debug };
    my $url = $redirect->sign($logoutreq, $foswiki_origin);
    Foswiki::Func::writeDebug("    Saml: logouturl url: ", $url) if $this->{Saml}{ debug };

    return $url;

}

=pod
---++ ObjectMethod login($query, $session)
The login method now acts as a switchboard. There are basically
two different uses of the login method.

First, it is used by the user agent to get a login page. We
detect this case by looking for the absence of all parameters
or for a provider=native parameter. The native provider is used
to display the original TemplateLogin page; in that case, this
login() method simply hands the query and session on to it's parent.

Second, it is used as a callback url by an Saml provider. We
detect this case by looking for state, code or error parameters.

There is one more case: When the provider parameter
is provided, we do an oauth redirect to the given provider.
=cut
sub login {
    my ( $this, $query, $session ) = @_;

    $this->loadSamlData();

    Foswiki::Func::writeDebug("SamlLoginContrib: login():") if $this->{Saml}{ debug };

    my $saml_response       = $query->param('SAMLResponse');
    my $relaystate          = $query->param('RelayState');
    my $provider            = $query->param('provider');
    my $saml                = $query->param('saml');
    my $origin              = $query->param('foswiki_origin');

    if ($this->{Saml}{ debug }) {
        Foswiki::Func::writeDebug("    SAML Query Parameters: $saml") if defined $saml;
        Foswiki::Func::writeDebug("        RelayState: $relaystate") if defined $relaystate;
        Foswiki::Func::writeDebug("        foswiki_origin: $origin") if defined $origin;
    }

    # Process the SAMLResponse
    # slo_redirect is a HTTP GET request for the response from a LogoutRequest
    if ( (defined $saml) && ($saml eq 'slo_redirect') && ( defined $saml_response ) ) {
        # This should be a GET request with "saml=slo_redirect"
        Foswiki::Func::writeDebug("    SAML $saml: $query->{method} received") if $this->{Saml}{ debug };
        my $originurl = $this->samlLogoutResponse($saml_response, $query, $session, $query->{method}, $relaystate);
        $query->deleteAll();
        $session->redirect( $originurl, 1 );
        return;
    }
    # FIXME: combine with above either this is a HPPT POST response for a LogoutRequest
    elsif ( ($query->{uri} =~ 'saml=slo_post' ) && ( defined $saml_response ) ) {
        #FIXME not sure whether to leave this seperate or combine with above
        # This should be a POST request with "saml=slo_post" as part of uri
        # $saml does not get set by the IdP as its POSTing to that as part of the URI
        Foswiki::Func::writeDebug("    SAML Logout $saml $query->{uri}: $query->{method} received")
            if $this->{Saml}{ debug };

        my $originurl = $this->samlLogoutResponse($saml_response, $query, $session, $query->{method}, $relaystate);
        $query->deleteAll();
        $session->redirect( $originurl, 1 );
        return;
    }
    # This is a Response for an AuthnRequest (the login response)
    elsif ( ( ($query->{uri} =~ 'saml=acs') && (defined $saml_response) ) || (defined $saml_response) ) {
        $query->deleteAll();
        # This should be a post to the ACS URL - $saml will never be set need the URI
        # Also a fail safe to be compatiable with older versions where the saml=acs
        # is not part of the URI
        Foswiki::Func::writeDebug("    SAMLResponse acs received $query->{uri}") if $this->{Saml}{ debug };
        $this->samlCallback($saml_response, $query, $session, $relaystate);
        return;
    }
    # Initiates the LogoutRequest process
    elsif ( $query->{uri} =~ 'saml=logout' ) {
        Foswiki::Func::writeDebug("    SAML Logout Initiation $saml $query->{uri}: $query->{method} received")
            if $this->{Saml}{ debug };

        my $url = $this->_logoutUrl( $origin );
        Foswiki::Func::writeDebug("    SAML Logout Initiation URL:", $url) if $this->{Saml}{ debug };

        $this->redirectToProvider($url, $query, $session);
        return;
    }
    # Overide the saml request to allow native login
    elsif ((defined $provider) && ($provider eq 'native')) {
        Foswiki::Func::writeDebug("    native login requested") if $this->{Saml}{ debug };
        # if we get a request for the native login
        # provider, we redirect to the original login
        $this->SUPER::login($query, $session);
        return;
    }
    elsif ((defined $provider) && ($provider ne 'native')) {
        Foswiki::Func::writeDebug(
            "    provider requested without native parameter") if $this->{Saml}{ debug };
        return;
    }
    # Generate a metatada for the Foswiki SP if parameter saml=metadata is received
    elsif ((defined $saml) && ($saml eq 'metadata')) {
        # Generate and return the metadata for Foswiki with the settings from
        # the LocalSite.cfg
        # FIXME: No real reason to protect this but need to think about it
        Foswiki::Func::writeDebug(
            "    request for metadata file") if $this->{Saml}{ debug };
        $session->{response}->header(
                                -type => 'application/octet-stream',
                                "Content-Disposition" => 'inline; filename="metadata.xml"',
                                );
        $session->{response}->body($this->getMetadata());
        return;
    }
    # Initiate the AuthnRequest to login
    else {
        $query->delete('SAMLResponse');
        $query->delete('foswiki_origin');
        $query->delete('Signature');
        $query->delete('SigAlg');
        # This initiates the login request to the IdentityProvider
        my $idp = Net::SAML2::IdP->new_from_url(
            url     => $this->{Saml}{ metadata},
            cacert  => $this->{Saml}{ cacert },
        );

        Foswiki::Func::writeDebug("    Net::SAML2::IdP created from url") if $this->{Saml}{ debug };
        Foswiki::Func::writeDebug("        Entity ID: $idp->{ entityid }") if $this->{Saml}{ debug };

        # Important not to return as XML here as we need to track the id for later verification
        my $authnreq = Net::SAML2::Protocol::AuthnRequest->new(
              issuer        => $this->{Saml}{ issuer },
              destination   => $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
              provider_name => $this->{Saml}{ provider_name },
        );

        if ( $this->{Saml}{ debug } ) {
            Foswiki::Func::writeDebug("    Net::SAML2::Protocol::AuthnRequest created");
            Foswiki::Func::writeDebug("        ID: $authnreq->{ id }");
        }

        # Store the request's id for later verification
        Foswiki::Func::setSessionValue('saml_request_id', $authnreq->{id});

        # Currently only supports HTTP-Redirect
        # FIXME Support HTTP-POST
        my $redirect = Net::SAML2::Binding::Redirect->new(
              key => $this->{Saml}{ sp_signing_key },
              cert => $this->{Saml}{ sp_signing_cert },
              param => 'SAMLRequest',
              url => $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        );

        Foswiki::Func::writeDebug("    Net::SAML2::Binding::Redirect created") if $this->{Saml}{ debug };

        # foswiki_origin is passed here as the RelayState
        my $url = $redirect->sign($authnreq->as_xml , $origin);

        Foswiki::Func::writeDebug("    $url") if $this->{Saml}{ debug };

        $this->redirectToProvider($url, $query, $session);
    }
}

=pod
---++ ObjectMethod getMetadata()
This is called directly by login() when login() detects a request
for Foswiki's metadata.  This will generate a metadata.xml file for
download.  This is also called by the Configure Wizard in configure
=cut

sub getMetadata {
    my $this = shift;

    my $org_name            = $Foswiki::cfg{Saml}{org_name} || 'Foswiki';
    my $org_display_name    = $Foswiki::cfg{Saml}{org_display_name} || 'Foswiki Saml Application';
    my $org_contact         = $Foswiki::cfg{Saml}{org_contact} || $Foswiki::cfg{WebMasterEmail};
    my $error_url           = $Foswiki::cfg{Saml}{error_url};
    my $slo_url_soap        = $Foswiki::cfg{Saml}{slo_url_soap} || '';
    my $slo_url_redirect    = $Foswiki::cfg{Saml}{slo_url_redirect};
    my $slo_url_post        = $Foswiki::cfg{Saml}{slo_url_post};
    my $acs_url_post        = $Foswiki::cfg{Saml}{acs_url_post};
    my $acs_url_artifact    = $Foswiki::cfg{Saml}{acs_url_artifact};
    my $url                 = $Foswiki::cfg{Saml}{url} || $Foswiki::cfg{Saml}{DefaultUrlHost};

    my $sp = Net::SAML2::SP->new(
        issuer => $Foswiki::cfg{Saml}{issuer},
        url    => $url,
        cert   => $Foswiki::cfg{Saml}{sp_signing_cert},
        key    => $Foswiki::cfg{Saml}{sp_signing_key},
        cacert => $Foswiki::cfg{Saml}{cacert},
        single_logout_service => [
        {
            Binding     => BINDING_HTTP_REDIRECT,
            Location    => $url . $slo_url_redirect,
        },
        {
            Binding     => BINDING_HTTP_POST,
            Location    => $url . $slo_url_post,
        },
        {
            Binding     => BINDING_HTTP_ARTIFACT,
            Location    => $url . $slo_url_soap,
        }],
        assertion_consumer_service => [
        {
            Binding     => BINDING_HTTP_POST,
            Location    => $url . $acs_url_post,
            isDefault   => 'false',
            # optionally
            index       => 1,
        },
        {
            Binding     => BINDING_HTTP_ARTIFACT,
            Location    => $url . $acs_url_artifact,
            isDefault   => 'true',
            index       => 2,
        }],
        error_url => $error_url,

        org_name     => $org_name,
        org_display_name => $org_display_name,
        org_contact  => $org_contact,
        sign_metadata => $Foswiki::cfg{Saml}{sign_metatdata},
    );

    return $sp->metadata;
}

=begin TML

---++ StaticMethod setUserFields ($session, $user, @emails)

=cut

sub setUserFields {
    my $this          = shift;
    my $cUID          = shift;
    my $attributes    = shift;

    my $session = $this->{session};
    my $user = $session->{users}->getWikiName($cUID);

    my $field_map = $Foswiki::cfg{Saml}{AttributeMap};

    my $topicObject =
      Foswiki::Meta->load( $session, $Foswiki::cfg{UsersWebName}, $user );

    if ( $topicObject->get('FORM') ) {

        foreach my $key (keys %$field_map) {
            # use the form if there is one
            $topicObject->putKeyed(
                'FIELD',
                {
                    name       => $key,
                    value      => $attributes->{${$field_map}{$key}}[0],
                    title      => $key,
                    attributes => 'h'
                }
            );
        }
    }
    else {
        # otherwise use the topic text
        my $text = $topicObject->text() || '';
        unless ( $text =~ s/^(\s+\*\s+First Name:\s*).*$/$1$attributes->{fname}/mi ) {
            foreach my $key (keys %$field_map) {
                if ($key =~ /Email/) { next;}
                $text .= "\n   * $key: $attributes->{${$field_map}{$key}}[0]\n";
            }
        }
        $topicObject->text($text);
    }

    $topicObject->save();
}
