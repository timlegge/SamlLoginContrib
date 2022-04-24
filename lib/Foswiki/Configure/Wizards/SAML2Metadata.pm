# See bottom of file for license and copyright information
package Foswiki::Configure::Wizards::SAML2Metadata;

=begin TML

---+ package Foswiki::Configure::Wizards::SAML2Metadata

Wizard to generate metadata.xml from configure

=cut

use strict;
use warnings;

use Assert;

use Foswiki::Configure::Wizard ();
our @ISA = ('Foswiki::Configure::Wizard');

=begin TML

---++ WIZARD generate

Generate Metadata for download

=cut

sub generate {
    my ( $this, $reporter, $root ) = @_;

    my $metadata = Foswiki::LoginManager::SamlLogin->getMetadata();
    $reporter->NOTE( <<HERE );
Your metadata has been generated and displayed below.  Please copy and import it at your Identitity Provider if applicable.
HERE
    $reporter->NOTE("<verbatim>$metadata</verbatim>");

    return undef;
}

1;
__END__
Foswiki - The Free and Open Source Wiki, http://foswiki.org/

Copyright (C) 2014-2022 Foswiki Contributors. Foswiki Contributors
are listed in the AUTHORS file in the root of this distribution.
NOTE: Please extend that file, not this notice.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version. For
more details read LICENSE in the root of this distribution.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

As per the GPL, removal of this notice is prohibited.
