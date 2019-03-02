# Module of Foswiki - The Free and Open Source Wiki, http://foswiki.org/
#
# Copyright (C) 2019 by Timothy Legge timlegge@gmail.com
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
use Net::SAML2;
use Data::Dumper;
use Net::SAML2::XML::Sig;
use MIME::Base64 qw/ decode_base64 /;
use Crypt::OpenSSL::VerifyX509;
use strict;
use warnings;
use Foswiki;
use Foswiki::LoginManager::TemplateLogin ();
use Foswiki::Sandbox ();

use Foswiki::Contrib::SamlContrib();

@Foswiki::LoginManager::SamlLogin::ISA = qw( Foswiki::LoginManager::TemplateLogin );

=begin TML

---++ ClassMethod new($session)

Construct the <nop> object

=cut

sub new {
  my ($class, $session) = @_;
  my $this = bless($class->SUPER::new($session), $class);
  undef $this->{metadata};
  undef $this->{cacert};
  undef $this->{sp_signing_key};
  undef $this->{sp_signing_cert};
  undef $this->{issuer};
  undef $this->{provider_name};
  undef $this->{saml_request_id};
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
    $this->{metadata} = $Foswiki::cfg{Saml}{metadata};
    $this->{cacert} = $Foswiki::cfg{Saml}{cacert};
    $this->{sp_signing_key} = $Foswiki::cfg{Saml}{sp_signing_key};
    $this->{sp_signing_cert} = $Foswiki::cfg{Saml}{sp_signing_cert};
    $this->{issuer} = $Foswiki::cfg{Saml}{issuer};
    $this->{provider_name} = $Foswiki::cfg{Saml}{provider_name};
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
    my $this = shift;
    my $attributes = shift;
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
    my $this = shift;
    my $nameid = shift;
#    my $login_attr = $this->{'loginname_attr'};
    my $login = $nameid;
    # SMELL: This is here to make valid login names out of MS Azure AD subject values. Probably shouldn't be
    # done here, and this explicitly.
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

    $this->{wikiname_attrs} = $Foswiki::cfg{'Saml'}{'WikiNameAttributes'};

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
    my $this = shift;
    my $wikiname = shift;
    my $email = shift;

    my $web = $Foswiki::cfg{'UsersWebName'} || 'Main';

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

    my $matches = Foswiki::Func::query("fields[name='$fieldname'].value=~'^\\s*$email\\s*\$'", ["$web.$wikiname"], $options);
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
    my $this = shift;
    my $session = shift;
    my $loginname = shift;
    my $wikiname = shift;

    # Currently, there doesn't seem to be a universal way to check
    # whether a mapping between login name and username is already
    # in place.
    my $is_mapped = 0;
    if ($Foswiki::cfg{Register}{AllowLoginName}) {
	my $aWikiname = Foswiki::Func::userToWikiName($loginname, 1);
	$is_mapped = $aWikiname ne $loginname;
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
    my $this = shift;
    my $session = shift;
    my $attributes = shift;
    my $nameid = shift;

    my $loginname = undef;
    my $candidate = $this->buildWikiName($attributes);
    if ($Foswiki::cfg{Register}{AllowLoginName}) {
	$loginname = $this->extractLoginname($nameid);
    }
    # SMELL: Turning off AllowLoginName for Open ID is a really bad idea. Should
    # we complain, or add a warning to the log?
    else {
	$loginname = $candidate;
    }

    my $email = lc($this->extractEmail($attributes));
    
    if (!$this->_isAlreadyMapped($session, $loginname, $candidate)) {
	my $wikiname = undef;
	my $orig_candidate = $candidate;
	my $counter = 1;
	# Find an acceptable wikiname. We simply add an increasing number if a name is taken already
	while (!defined($wikiname)) {
	    my $users = $session->{users}->findUserByWikiName($candidate);
	    if (scalar @$users == 0) {
		$wikiname = $this->matchWikiUser($candidate, $email);
		Foswiki::Func::writeDebug("Saml: matchWikiUser for $candidate produces $wikiname") if $Foswiki::cfg{Saml}{Debug};
		if (defined $wikiname) {
		    my $cuid = $session->{'users'}->addUser($loginname, $wikiname, undef, [$email]);
		        Foswiki::Func::writeDebug("Saml Mapped user $cuid ($email) to $wikiname") if $Foswiki::cfg{Saml}{Debug};
		    return $cuid;
		}
	    }
	    $counter = $counter + 1;
	    $candidate = $orig_candidate . $counter;
	}
    } else {
	# Mapping exists already, so return the canonical user id
	my $cuid = $session->{users}->getCanonicalUserID($loginname);
	Foswiki::Func::writeDebug("Saml Use preexisting mapping for $loginname") if $Foswiki::cfg{Saml}{Debug};
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
    my $this = shift;
    my $request_url = shift;
    my $query = shift;
    my $session = shift;

    my $origin = $query->param('foswiki_origin');
    # Avoid accidental passthrough
    $query->delete( 'foswiki_origin');

    my $topic = $session->{topicName};
    my $web = $session->{webName};

    $this->loadSamlData();

    my $response = $session->{response};

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
    my $this = shift;
    my $saml_response = shift;
    my $query = shift;
    my $session = shift;

    my $origin = $this->getAndClearSessionValue('saml_origin');
    my $web = $this->getAndClearSessionValue('saml_web');
    my $topic = $this->getAndClearSessionValue('saml_topic');

    # Don't show the SAMLReponse in the URL
    $query->delete('SAMLResponse');

    $this->{cacert} = $Foswiki::cfg{Saml}{cacert};

    #  Create the POST binding object to get the details from the SALMResponse'
    my $post = Net::SAML2::Binding::POST->new(cacert => $this->{cacert});

    # Send the SAMLResponse to the Binding for the POST
    # The return has the CA certificate Subject and verified if correct
    my $ret = $post->handle_response(
        $saml_response
    );
        
    if ($ret) {
        if ( $Foswiki::cfg{Saml}{Debug} == 1 ) {
            print STDERR $ret;
        }
        my $assertion = Net::SAML2::Protocol::Assertion->new_from_xml(
            xml => decode_base64($saml_response)
        );
=pod
	Verify that the response was related to the request
	the issuer and the id from the Saml Authnreq must be sent to the Assertion->valid()
	probably a better way to track the id/inresponseto
=cut
	my $issuer = $Foswiki::cfg{Saml}{issuer};
	my $saml_request_id = $this->getAndClearSessionValue('saml_request_id');

	# $assertion->valid() checks the dates and the audience
	my $valid = $assertion->valid($issuer, $saml_request_id);

        if (!$valid) {
            print STDERR "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ERROR INVALID ^^^^^^^^^^^^^^^^^^^\n";
	    Foswiki::Func::writeDebug("samlCallback: SAMLResponse \"InResponseTo\" does not match request ID") if $Foswiki::cfg{Saml}{Debug};
	}
	else {
            # The audience and the dates NotBefore and NotOnOrAfter are correct
            if ( $Foswiki::cfg{Saml}{Debug} == 1 ) {
                # output the attributes and values that are available in the response
		keys %{$assertion->attributes};
                while(my($k, $v) = each %{$assertion->attributes}) {
                    print STDERR $k . " >>> " . %$v[0];
                }
	    }
    	    my $cuid = $this->mapUser($session, $assertion->attributes, $assertion->nameid);
	
            # SMELL: This isn't part of the public API! But Foswiki::Func doesn't provide login name lookup and
            # wikiname lookup doesn't work yet at that stage (yields the loginname, ironically...)
            my $wikiname = $session->{users}->getWikiName($cuid);
            my $loginName = $session->{users}->getLoginName($cuid);

            $this->userLoggedIn($loginName);
            $session->logger->log({
                level    => 'info',
                action   => 'login',
                webTopic => $web . '.' . $topic,
                extra    => "AUTHENTICATION SUCCESS - $loginName ($wikiname) - "
            });

            my ( $origurl, $origmethod, $origaction ) = Foswiki::LoginManager::TemplateLogin::_unpackRequest($origin);
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
	    #print STDERR Dumper($origurl);
            $session->redirect( $origurl, 1 );
            return;
        }
    }
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

    my $provider             = $query->param('provider');
    my $metadata	     = $Foswiki::cfg{Saml}{metadata};
    my $cacert               = $Foswiki::cfg{Saml}{cacert};
    my $sp_signing_key      = $Foswiki::cfg{Saml}{sp_signing_key};
    my $sp_signing_cert     = $Foswiki::cfg{Saml}{sp_signing_cert};
    my $issuer               = $Foswiki::cfg{Saml}{issuer};
    my $provider_name        = $Foswiki::cfg{Saml}{provider_name};

    my $saml_response = $query->param('SAMLResponse');

    if (defined $saml_response) {
        $this->samlCallback($saml_response, $query, $session);
    }
    elsif ((defined $provider) && ($provider eq 'native')) {
	# if we get a request for the native login 
	# provider, we redirect to the original login
	$this->SUPER::login($query, $session);
    }
    elsif ((defined $provider) && ($provider ne 'native')) {
	return;
    }
    else {
        my $idp = Net::SAML2::IdP->new_from_url(url => $metadata, cacert => $cacert);
	#print STDERR Dumper($idp);

	# Important not to return as XML here as we need to track the id for later verification
	my $authnreq = Net::SAML2::Protocol::AuthnRequest->new(
              issuer        => $issuer,
              destination   => $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'), # The ssl_url destination for redirect
              provider_name => $provider_name,
        );

	#print STDERR Dumper($authnreq);

	# Store the request's id for later verification
	Foswiki::Func::setSessionValue('saml_request_id', $authnreq->id);

        my $redirect = Net::SAML2::Binding::Redirect->new(
              key => $sp_signing_key,
              cert => $sp_signing_cert,
              param => 'SAMLRequest',
              url => $idp->sso_url('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'), # The ssl_url destination for redirect
        );
        #print STDERR Dumper($redirect);

        my $url = $redirect->sign($authnreq->as_xml);
        #print Dumper($url);
    
        $this->redirectToProvider($url, $query, $session);
    }
}
