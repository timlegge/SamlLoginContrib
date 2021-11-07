# Module of Foswiki - The Free and Open Source Wiki, http://foswiki.org/
#
# Copyright (C) 2021-2019 by Timothy Legge timlegge@gmail.com
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

use LWP;
use LWP::UserAgent;
use Net::SAML2 0.44;
use Data::Dumper;
use Net::SAML2::XML::Sig;
use MIME::Base64 qw/ decode_base64 /;
use strict;
use warnings;
use Foswiki;
use Foswiki::LoginManager::TemplateLogin ();
use Foswiki::Sandbox ();

use Foswiki::Contrib::SamlLoginContrib();

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
    }
}

sub getAndClearSessionValue {
    my $this = shift;
    my $key = shift;

    my $value = Foswiki::Func::getSessionValue($key);
    Foswiki::Func::clearSessionValue($key);

    return $value;
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

    return undef;
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

    my $origin      = $query->param('foswiki_origin');

    # Avoid accidental passthrough
    $query->delete('foswiki_origin');

    my $topic       = $session->{topicName};
    my $web         = $session->{webName};
    my $response    = $session->{response};

    if ( $this->{Saml}{ debug } ) {
        Foswiki::Func::writeDebug("    redirectToProvider set session values");
        Foswiki::Func::writeDebug("        foswiki_origin: $origin");
        Foswiki::Func::writeDebug("        topicName: $topic");
        Foswiki::Func::writeDebug("        webName:   $web");
        Foswiki::Func::writeDebug("        response:",  Dumper($response));
    }

    Foswiki::Func::setSessionValue('saml_origin', $origin);
    Foswiki::Func::setSessionValue('saml_web', $web);
    Foswiki::Func::setSessionValue('saml_topic', $topic);

    $response->redirect($request_url);
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

    my $origin  = $this->getAndClearSessionValue('saml_origin');
    my $web     = $this->getAndClearSessionValue('saml_web');
    my $topic   = $this->getAndClearSessionValue('saml_topic');

    Foswiki::Func::writeDebug(
        "    samlCallback") if $this->{Saml}{ debug };

    # Store now as is it used in several places in the code below
    my ( $origurl, $origmethod, $origaction ) =
        Foswiki::LoginManager::TemplateLogin::_unpackRequest($origin);

    if ($query->{method} eq 'GET') {
        my $sessionindex = $this->getAndClearSessionValue('saml_session_index');
        my $idp = Net::SAML2::IdP->new_from_url(
            url     => $this->{Saml}{metadata},
            cacert  => $this->{Saml}{cacert},
            sls_force_lcase_url_encoding => $this->{Saml}{sls_force_lcase_url_encoding},
            sls_double_encoded_response => $this->{Saml}{sls_double_encoded_response}
        );

        my $redirect = Net::SAML2::Binding::Redirect->new(
            url   => $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
            key => $this->{Saml}{sp_signing_key},
            cert => $idp->cert('signing'),
            param => 'SAMLResponse',
            sls_force_lcase_url_encoding => $this->{Saml}{sls_force_lcase_url_encoding},
            sls_double_encoded_response => $this->{Saml}{sls_double_encoded_response}
        );

        my ($response, $relaystate) = $redirect->verify($query->{uri});

        if ($response) {
            my $logout = Net::SAML2::Protocol::LogoutResponse->new_from_xml(
                            xml => $response
            );

            if ($logout->status eq 'urn:oasis:names:tc:SAML:2.0:status:Success') {
                $this->{_cgisession}->delete();
                $this->{_cgisession}->flush();
                $this->{_cgisession} = undef;
                $this->_delSessionCookieFromResponse();

                #my $authUser =
                #$this->redirectToLoggedOutUrl( $authUser, $defaultUser );
                $session->{request}->delete('logout');

                print STDERR "\nLogout Success Status - $logout->{issuer}\n";
            }
        }
        else {
            return "<html><pre>Bad Logout Response</pre></html>";
        }
#    redirect $relaystate || '/', 302;
#    return "Redirected\n";

    }
    else {

        # Don't show the SAMLReponse in the URL
        $query->delete('SAMLResponse');
        #  Create the POST binding object to get the details from the SALMResponse'
        my $post = Net::SAML2::Binding::POST->new(cacert => $this->{Saml}{cacert});

        Foswiki::Func::writeDebug("    Net::SAML2::Binding::POST created") if $this->{Saml}{ debug };

        # Send the SAMLResponse to the Binding for the POST
        # The return has the CA certificate Subject and verified if correct
        my $ret = $post->handle_response(
                $saml_response
        );

        if ($ret) {
        Foswiki::Func::writeDebug(
        "        SAMLResponse handled successfully by POST") if $this->{Saml}{ debug };

        my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
            xml => decode_base64($saml_response)
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
            # Always print this in debug as the chances of this occuring is rare
            Foswiki::Func::writeDebug("        SAML assertion is invalid");
            Foswiki::Func::writeDebug("            Issuer:       $issuer");
            Foswiki::Func::writeDebug("            InResponseTo: $saml_request_id");
            Foswiki::Func::writeDebug("            SessionIndex: $assertion->{ session }");
            Foswiki::Func::writeDebug("            NotBefore:    $assertion->{ not_before }");
            Foswiki::Func::writeDebug("            NotAfter:     $assertion->{ not_after }");

            #FIXME: Possibly move to a function (used below too!)
            $query->method($origmethod);
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

            Foswiki::Func::writeDebug("            Assertion NameID $assertion->nameid")
                if $this->{Saml}{ debug };

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
                            # SMELL: Removed TAINT on $2 because couldn't figure out where it was defined
                            $query->param( $1, $2 );
                        }
                    }
                }

                # Restore the action too
                $query->action($origaction) if $origaction;
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
    my $this = $session->getLoginManager();

    return $this->logoutUrl(@_);

}

sub _LOGOUT {
    my ( $session, $params, $topic, $web ) = @_;
    my $this = $session->getLoginManager();

    return '' unless $session->inContext('authenticated');

    my $url = _LOGOUTURL(@_);
    if ($url) {
        my $text = $session->templates->expandTemplate('LOG_OUT');
        return CGI::a( { href => $url }, $text );
    }
    return '';
}

=begin TML

---++ ObjectMethod logoutUrl () -> $logoutUrl

Overrides LoginManager. Content of a logout link.

=cut

sub logoutUrl {
    my $this = shift;
    my ( $session, $params, $topic, $web ) = @_;

    my $sessionindex = $this->getSessionValue('saml_session_index');
    Foswiki::Func::writeDebug("Saml: SessionIndex: $sessionindex");# if $this->{Saml}{ debug };

    $this->loadSamlData();
    Foswiki::Func::writeDebug("Saml: logouturl got here:");# if $this->{Saml}{ debug };

    my $idp = Net::SAML2::IdP->new_from_url(
        url     => $this->{Saml}{ metadata},
        cacert  => $this->{Saml}{ cacert },
    );

    Foswiki::Func::writeDebug("Saml: logouturl WikiName: $session->{user}");# if $this->{Saml}{ debug };
    my $users = $session->{users}->getLoginName($session->{user});

    Foswiki::Func::writeDebug("Saml: logouturl Users: ", Dumper($session->{user}));# if $this->{Saml}{ debug };
    my $logoutrequest = Net::SAML2::Protocol::LogoutRequest->new(
        issuer        => $this->{Saml}{ issuer },
        nameid_format => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
        destination   => $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        nameid      => $session->{users}->getLoginName($session->{user}),
        session     => $sessionindex,
    );

    my $logoutreq = $logoutrequest->as_xml;

    my $redirect =   my $redirect = Net::SAML2::Binding::Redirect->new(
              key => $this->{Saml}{ sp_signing_key },
              cert => $this->{Saml}{ sp_signing_cert },
              destination   => $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
              param => 'SAMLRequest',
              url   => $idp->slo_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
  );
    my $url = $redirect->sign($logoutreq);

    Foswiki::Func::writeDebug("Saml: logouturl url: ", $url);# if $this->{Saml}{ debug };

    return $url;

}

=pod
---++ ObjectMethod logout ($thisl)


=cut

sub logout {
    my ( $this, $session, $params, $topic, $web ) = @_;

    $this->loadSamlData();
    return '' unless $session->inContext('authenticated');

    my $url = logoutUrl(@_);

    if ($url) {
        my $text = $session->templates->expandTemplate('LOG_OUT');
        return CGI::a( { href => $url }, $text );
    }
    return '';
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
    my $provider            = $query->param('provider');

    # Process the SAMLResponse
    if (defined $saml_response) {
        Foswiki::Func::writeDebug("    SAMLResponse received") if $this->{Saml}{ debug };
        $this->samlCallback($saml_response, $query, $session);
    }
    elsif ((defined $provider) && ($provider eq 'native')) {
        Foswiki::Func::writeDebug("    native login requested") if $this->{Saml}{ debug };
        # if we get a request for the native login
        # provider, we redirect to the original login
        $this->SUPER::login($query, $session);
    }
    elsif ((defined $provider) && ($provider ne 'native')) {
        Foswiki::Func::writeDebug(
            "    provider requested without native parameter") if $this->{Saml}{ debug };
        return;
    }
    else {
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
        Foswiki::Func::setSessionValue('saml_request_id', $authnreq->id);

        my $redirect = Net::SAML2::Binding::Redirect->new(
              key => $this->{Saml}{ sp_signing_key },
              cert => $this->{Saml}{ sp_signing_cert },
              param => 'SAMLRequest',
              url => $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        );

        Foswiki::Func::writeDebug("    Net::SAML2::Binding::Redirect created") if $this->{Saml}{ debug };

        my $url = $redirect->sign($authnreq->as_xml);

        Foswiki::Func::writeDebug("    $url") if $this->{Saml}{ debug };

        $this->redirectToProvider($url, $query, $session);
    }
}
