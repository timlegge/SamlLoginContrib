# See bottom of file for license and copyright information
package Foswiki::Contrib::SamlLoginContrib::AttributeStore;

=begin TML

---+ package Foswiki::Contrib::SamlLoginContrib::AttributeStore

Persists the attributes of a Saml assertion so that they can be read back on
later requests, by anyone, long after the assertion itself is gone.

An Identity Provider only speaks to us once, during the ACS POST, so whatever
we want to show on a user's topic afterwards has to be kept here.

The store is a DB_File hash under {WorkingDir}, holding one JSON-encoded
attribute hash per login name:

   * =LOGINNAMES= - newline separated list of every login name in the store
   * =U2A::$loginName= - the assertion attributes of $loginName, as JSON

Values are stored exactly as the Identity Provider sent them.  Escaping is the
caller's business, and depends on where the value is going - see
=Foswiki::LoginManager::SamlLogin::_escapeAttribute= for topic text.

=cut

use strict;
use warnings;

use DB_File::Lock ();
use Fcntl qw(O_CREAT O_RDWR O_RDONLY);
use JSON ();
use Foswiki::Func ();

our $JSON = JSON->new->canonical(1)->utf8(1);

=begin TML

---++ ClassMethod new() -> $store

=cut

sub new {
    my $class = shift;

    my $this = bless(
        {
            file => $Foswiki::cfg{Saml}{AttributeStoreFile}
              || Foswiki::Func::getWorkArea('SamlLoginContrib')
              . '/attributes.db',
        },
        $class
    );

    return $this;
}

# Tie the db for the duration of $code and hand the tied hash to it.  DB_File
# is not concurrency safe on its own; DB_File::Lock takes a read or write lock
# on the file for as long as the hash is tied, which is why every access here
# is wrapped rather than the handle being kept open across requests.
sub _withDB {
    my ( $this, $mode, $code ) = @_;

    my %db;
    my $flags = $mode eq 'write' ? O_CREAT | O_RDWR : O_RDONLY;

    # Nothing has been written yet, so there is nothing to read.  Reading is
    # much the commoner case - every render of a user topic does it - so this
    # must not create the file as a side effect.
    return undef if $mode ne 'write' && !-e $this->{file};

    my $tied = tie( %db, 'DB_File::Lock', $this->{file}, $flags, 0664,
        $DB_File::DB_HASH, $mode );

    unless ($tied) {
        Foswiki::Func::writeWarning(
            "SamlLoginContrib: cannot open attribute store $this->{file}: $!");
        return undef;
    }

    my $result = eval { $code->( \%db ) };
    my $error = $@;

    undef $tied;
    untie %db;

    die $error if $error;
    return $result;
}

=begin TML

---++ ObjectMethod put($loginName, $attributes) -> $boolean

Stores the assertion attributes of $loginName, replacing anything held for
that login already.  $attributes is the hash Net::SAML2 hands back, mapping an
attribute name to an array reference of values.

=cut

sub put {
    my ( $this, $loginName, $attributes ) = @_;

    return 0 unless defined $loginName && $loginName ne '';
    return 0 unless ref($attributes) eq 'HASH';

    return $this->_withDB(
        'write',
        sub {
            my $db = shift;

            $db->{ 'U2A::' . $loginName } = $JSON->encode($attributes);

            my %known = map { $_ => 1 } split( /\n/, $db->{LOGINNAMES} || '' );
            unless ( $known{$loginName} ) {
                $known{$loginName} = 1;
                $db->{LOGINNAMES} = join( "\n", sort keys %known );
            }

            return 1;
        }
    ) || 0;
}

=begin TML

---++ ObjectMethod get($loginName) -> \%attributes

Returns the stored attributes of $loginName, or undef when the login has never
logged in through Saml (or the store has been removed).

=cut

sub get {
    my ( $this, $loginName ) = @_;

    return undef unless defined $loginName && $loginName ne '';

    return $this->_withDB(
        'read',
        sub {
            my $db = shift;

            my $json = $db->{ 'U2A::' . $loginName };
            return undef unless defined $json && $json ne '';

            my $attributes = eval { $JSON->decode($json) };
            unless ( ref($attributes) eq 'HASH' ) {
                Foswiki::Func::writeWarning(
                    "SamlLoginContrib: unreadable attributes for $loginName: $@"
                );
                return undef;
            }

            return $attributes;
        }
    );
}

=begin TML

---++ ObjectMethod getValue($loginName, $attribute) -> $value

Returns the first value of one attribute, or undef.  Multi valued attributes
are the norm in Saml - every value in an assertion is a list - and almost
every caller wants the first one.

=cut

sub getValue {
    my ( $this, $loginName, $attribute ) = @_;

    my $attributes = $this->get($loginName);
    return undef unless $attributes;

    my $values = $attributes->{$attribute};
    return undef unless ref($values) eq 'ARRAY' && @$values;

    return $values->[0];
}

=begin TML

---++ ObjectMethod getLoginNames() -> \@loginNames

Returns every login name the store knows about, sorted.

=cut

sub getLoginNames {
    my $this = shift;

    my $list = $this->_withDB( 'read', sub { return shift->{LOGINNAMES} } );

    return [] unless defined $list && $list ne '';
    return [ split( /\n/, $list ) ];
}

=begin TML

---++ ObjectMethod remove($loginName) -> $boolean

Forgets a login.  Nothing calls this yet; it is here so that a site can drop a
departed user's attributes without deleting the whole store.

=cut

sub remove {
    my ( $this, $loginName ) = @_;

    return 0 unless defined $loginName && $loginName ne '';

    return $this->_withDB(
        'write',
        sub {
            my $db = shift;

            delete $db->{ 'U2A::' . $loginName };

            my %known = map { $_ => 1 } split( /\n/, $db->{LOGINNAMES} || '' );
            delete $known{$loginName};
            $db->{LOGINNAMES} = join( "\n", sort keys %known );

            return 1;
        }
    ) || 0;
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
