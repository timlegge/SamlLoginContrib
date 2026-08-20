# See bottom of file for license and copyright information
package Foswiki::Plugins::SamlLoginPlugin;

=begin TML

---+ package Foswiki::Plugins::SamlLoginPlugin

The rendering and indexing half of SamlLoginContrib.

=Foswiki::LoginManager::SamlLogin= receives the assertion and stores its
attributes; this plugin is what lets the rest of the wiki see them.  It has to
be a plugin rather than more of the contrib because both of the things it does
- registering macros and registering a Solr index handler - can only be done
from =initPlugin=.

This mirrors how the Ldap extensions are split: LdapContrib does the
authentication and the caching, LdapNgPlugin supplies =%LDAP%=, =%LDAPUSERS%=
and the Solr =indexTopicHandler=.

=cut

use strict;
use warnings;

use Foswiki::Func ();
use Foswiki::Plugins ();

our $VERSION = '1.00';
our $RELEASE = '19 Aug 2026';
our $SHORTDESCRIPTION =
  'Renders and indexes the Saml assertion attributes gathered at login';
our $NO_PREFS_IN_TOPIC = 1;

our $store;

sub initPlugin {

    Foswiki::Func::registerTagHandler( 'SAML',      \&_handleSaml );
    Foswiki::Func::registerTagHandler( 'SAMLUSERS', \&_handleSamlUsers );

    # Put the attributes into the Solr document even though they are not in
    # the topic.  Without this a site that renders its user topics through
    # %SAML{...}% - rather than by writing the values into the UserForm - has
    # nothing for Solr to index, and searching for a colleague by phone number
    # or department finds nobody.
    if ( $Foswiki::cfg{Plugins}{SolrPlugin}{Enabled}
        && eval { require Foswiki::Plugins::SolrPlugin; 1 } )
    {
        Foswiki::Plugins::SolrPlugin::registerIndexTopicHandler(
            \&indexTopicHandler );
    }

    undef $store;

    return 1;
}

sub finishPlugin {
    undef $store;
}

sub _getStore {
    unless ( defined $store ) {
        require Foswiki::Contrib::SamlLoginContrib::AttributeStore;
        $store = Foswiki::Contrib::SamlLoginContrib::AttributeStore->new();
    }
    return $store;
}

# Values arrive from the Identity Provider, so they are not trusted.  A phone
# number containing %SEARCH{...}% would otherwise be expanded with the rights
# of whoever views the topic.
sub _escape {
    my $value = shift;
    return '' unless defined $value;
    return Foswiki::entityEncode( $value, "\n\r" );
}

# Resolve whatever the caller named - a wikiname, a Main.WikiName, or a login
# name - to the login name the store is keyed by.
sub _loginNameOf {
    my $who = shift;

    return undef unless defined $who && $who ne '';

    my ( undef, $wikiName ) =
      Foswiki::Func::normalizeWebTopicName( $Foswiki::cfg{UsersWebName}, $who );

    my $loginName = Foswiki::Func::wikiToUserName($wikiName);

    # wikiToUserName hands back what it was given when there is no mapping,
    # which is the right answer when the caller passed a login name to start
    # with, and the only answer available when the user has no mapping yet.
    return $loginName || $wikiName;
}

# The obvious Foswiki::Func::userToWikiName($loginName, 1) is no good here: it
# hands back the login name unchanged until the user's topic exists, which is
# precisely the case this plugin was written for - the topic is created a
# request later than the login that fills the store.  Going through the
# canonical user id resolves whether or not the topic is there.
sub _wikiNameOf {
    my $loginName = shift;

    return '' unless defined $loginName && $loginName ne '';

    my $cUID = Foswiki::Func::getCanonicalUserID($loginName);
    return $loginName unless defined $cUID;

    return Foswiki::Func::getWikiName($cUID) || $loginName;
}

# The store is the only copy of the assertion attributes: it lives under
# {WorkingDir}, is not versioned, is not part of a topic backup, and - unlike
# an Ldap cache - cannot be rebuilt, because the Identity Provider describes a
# user only while that user is logging in.  Deleting it would otherwise blank
# every user's page until each of them happened to log in again.
#
# The UserForm that setUserFields writes is the durable copy of the same
# values, so fall back to reading that.  It only carries the fields named in
# {Saml}{AttributeMap}, so $attr(...) for an unmapped attribute stays empty on
# this path.
sub _attributesFromForm {
    my $wikiName = shift;

    my $map = $Foswiki::cfg{Saml}{AttributeMap};
    return undef unless ref($map) eq 'HASH' && keys %$map;
    return undef unless defined $wikiName && $wikiName ne '';

    my $usersWeb = $Foswiki::cfg{UsersWebName};
    return undef unless Foswiki::Func::topicExists( $usersWeb, $wikiName );

    my ($meta) = Foswiki::Func::readTopic( $usersWeb, $wikiName );
    return undef unless $meta;

    my $personDataForm = $Foswiki::cfg{Saml}{PersonDataForm} || 'UserForm';
    my $formName = $meta->getFormName();
    return undef unless $formName && $formName =~ /$personDataForm/;

    my $attributes = {};
    foreach my $field ( keys %$map ) {
        my $entry = $meta->get( 'FIELD', $field );
        next unless $entry && defined $entry->{value} && $entry->{value} ne '';

        # setUserFields entity encoded these on the way in.  Decode, so that
        # the value here looks exactly as the assertion delivered it and is
        # encoded once rather than twice on the way back out.
        $attributes->{ $map->{$field} } =
          [ Foswiki::entityDecode( $entry->{value} ) ];
    }

    return keys %$attributes ? $attributes : undef;
}

# $FirstName style tokens come from the keys of {Saml}{AttributeMap}, so a
# format string is written in terms of the same field names the UserForm uses
# rather than in raw urn:oid attribute names.
sub _expandTokens {
    my ( $format, $attributes, %extra ) = @_;

    my $result = $format;
    my $map    = $Foswiki::cfg{Saml}{AttributeMap};

    # $attr(urn:oid:2.5.4.42) reaches an attribute the map does not name.
    $result =~ s/\$attr\(\s*(.*?)\s*\)/_firstValue($attributes, $1)/ge;

    if ( ref($map) eq 'HASH' ) {
        foreach my $field ( sort { length($b) <=> length($a) } keys %$map ) {
            my $value = _firstValue( $attributes, $map->{$field} );
            $result =~ s/\$\Q$field\E\b/$value/g;
        }
    }

    foreach my $key ( sort { length($b) <=> length($a) } keys %extra ) {
        my $value = defined $extra{$key} ? $extra{$key} : '';
        $result =~ s/\$\Q$key\E\b/$value/g;
    }

    return $result;
}

# Every value in an assertion is a list, and almost every caller wants the
# first one.
sub _rawValue {
    my ( $attributes, $attribute ) = @_;

    return '' unless ref($attributes) eq 'HASH' && defined $attribute;

    my $values = $attributes->{$attribute};
    return '' unless ref($values) eq 'ARRAY' && @$values;

    return defined $values->[0] ? $values->[0] : '';
}

# Escaped for use in wiki text.  Not for Solr: a document field holding
# timlegge&#64;gmail.com does not match a search for timlegge@gmail.com, and
# nothing renders a Solr field as TML, so there is nothing to protect there.
sub _firstValue {
    my ( $attributes, $attribute ) = @_;

    return _escape( _rawValue( $attributes, $attribute ) );
}

=begin TML

---++ StaticMethod _handleSaml($session, $params, $topic, $web) -> $string

Implements =%<nop>SAML{...}%=

   * =_DEFAULT= or =user= - whose attributes to show.  Defaults to the topic
     being rendered, so a user topic can simply say =%SAML{format="..."}%=
   * =format= - defaults to =$FirstName $LastName=
   * =default= - returned when the user has never logged in through Saml

=cut

sub _handleSaml {
    my ( $session, $params, $topic, $web ) = @_;

    my $who = $params->{_DEFAULT} || $params->{user} || $topic;
    my $format = $params->{format};
    $format = '$FirstName $LastName' unless defined $format;

    my $loginName = _loginNameOf($who);
    my $wikiName = defined $loginName ? _wikiNameOf($loginName) : $who;

    my $attributes;
    $attributes = _getStore()->get($loginName) if defined $loginName;

    # The store wins when it has something: it holds every attribute the
    # assertion carried, not just the mapped ones, and it is refreshed on
    # every login.
    $attributes = _attributesFromForm($wikiName) unless $attributes;

    return defined $params->{default} ? $params->{default} : ''
      unless $attributes;

    my $result = _expandTokens(
        $format, $attributes,
        loginName => defined $loginName ? $loginName : '',
        wikiName  => $wikiName,
    );

    return Foswiki::Func::decodeFormatTokens($result);
}

=begin TML

---++ StaticMethod _handleSamlUsers($session, $params, $topic, $web) -> $string

Implements =%<nop>SAMLUSERS{...}%=, the counterpart of =%<nop>LDAPUSERS%=: a
formatted list of everyone who has logged in through Saml, built from the
attribute store rather than from the user topics, so it reaches values that
were never written into a UserForm.

   * =format= - defaults to =   * $displayName=
   * =header=, =footer=, =separator= (=sep=)
   * =limit=, =skip=
   * =include=, =exclude= - regular expressions matched against the wikiname
   * =casesensitive= - defaults to on, as =%<nop>LDAPUSERS%= does
   * =hideunknown= - skip users with no topic in the users web, defaults to on

=cut

sub _handleSamlUsers {
    my ( $session, $params, $topic, $web ) = @_;

    my $format = $params->{format};
    $format = '   * $displayName' unless defined $format;

    my $separator = $params->{separator};
    $separator = $params->{sep} unless defined $separator;
    $separator = '$n' unless defined $separator;

    my $header        = $params->{header} || '';
    my $footer        = $params->{footer} || '';
    my $include       = $params->{include};
    my $exclude       = $params->{exclude};
    my $casesensitive = Foswiki::Func::isTrue( $params->{casesensitive}, 1 );
    my $hideUnknown   = Foswiki::Func::isTrue( $params->{hideunknown},   1 );

    my $limit = $params->{limit} || 0;
    my $skip  = $params->{skip}  || 0;
    $limit =~ s/[^\d]//g;
    $skip  =~ s/[^\d]//g;

    my $usersWeb = $Foswiki::cfg{UsersWebName};
    my $store    = _getStore();

    my @rows;
    foreach my $loginName ( @{ $store->getLoginNames() } ) {
        my $wikiName = _wikiNameOf($loginName);

        if ($casesensitive) {
            next if defined $exclude && $wikiName =~ /$exclude/;
            next if defined $include && $wikiName !~ /$include/;
        }
        else {
            next if defined $exclude && $wikiName =~ /$exclude/i;
            next if defined $include && $wikiName !~ /$include/i;
        }

        my $exists = Foswiki::Func::topicExists( $usersWeb, $wikiName );
        next if $hideUnknown && !$exists;

        push @rows,
          {
            loginName => $loginName,
            wikiName  => $wikiName,
            displayName => $exists
            ? "[[$usersWeb.$wikiName]]"
            : "<nop>$wikiName",
          };
    }

    @rows = sort { $a->{wikiName} cmp $b->{wikiName} } @rows;

    my @result;
    my $index = 0;
    foreach my $row (@rows) {
        $index++;
        next if $index <= $skip;

        my $attributes = $store->get( $row->{loginName} ) || {};

        push @result,
          _expandTokens(
            $format, $attributes,
            index       => $index,
            loginName   => $row->{loginName},
            wikiName    => $row->{wikiName},
            displayName => $row->{displayName},
          );

        last if $limit && scalar(@result) >= $limit;
    }

    my $result = $header . join( $separator, @result ) . $footer;
    $result =~ s/\$count\b/scalar(@result)/ge;

    return Foswiki::Func::decodeFormatTokens($result);
}

=begin TML

---++ StaticMethod indexTopicHandler($indexer, $doc, $web, $topic, $meta, $text)

Adds the stored assertion attributes to the Solr document of a user topic.

The fields are named the way SolrPlugin names form fields, =field_<name>_s=
and =field_<name>_search=, so an attribute that only exists in the store is
searchable on exactly the same terms as one that was written into the
UserForm.  This is the same trick =LdapNgPlugin= plays, minus the directory
lookup.

=cut

sub indexTopicHandler {
    my ( $indexer, $doc, $web, $topic, $meta, $text ) = @_;

    my $map = $Foswiki::cfg{Saml}{AttributeMap};
    return unless ref($map) eq 'HASH' && keys %$map;

    return unless $web eq $Foswiki::cfg{UsersWebName};

    my $personDataForm = $Foswiki::cfg{Saml}{PersonDataForm} || 'UserForm';

    ($meta) = Foswiki::Func::readTopic( $web, $topic ) unless $meta;
    my $formName = $meta->getFormName();
    return unless $formName && $formName =~ /$personDataForm/;

    my $loginName = _loginNameOf($topic);
    return unless defined $loginName;

    my $attributes = _getStore()->get($loginName);
    return unless $attributes;

    foreach my $field ( keys %$map ) {
        my $value = _rawValue( $attributes, $map->{$field} );
        next if $value eq '';

        _setField( $doc, 'field_' . $field . '_s',      $value );
        _setField( $doc, 'field_' . $field . '_search', $value );
    }

    return;
}

# A Solr document is append only, so a field that the topic already carried -
# because setUserFields wrote it into the UserForm as well - has to be removed
# before the stored value replaces it, or the document ends up with both.
sub _setField {
    my ( $doc, $name, $value ) = @_;

    # The WebService::Solr::Document Foswiki ships has no remove_fields, so
    # rebuild the list without this name.  LdapNgPlugin edits the first
    # matching field in place instead, which leaves the remaining values of a
    # multi-valued field behind.
    my @keep = grep { $_->name ne $name } $doc->fields;
    $doc->fields( \@keep );
    $doc->add_fields( $name => $value );

    return;
}

1;
__END__
Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Copyright (C) 2026 Foswiki Contributors. Foswiki Contributors
are listed in the AUTHORS file in the root of this distribution.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version. For
more details read LICENSE in the root of this distribution.
