FROM alpine:edge

ENV PERL_MM_USE_DEFAULT 1

ENV FOSWIKI_LATEST_URL https://foswiki.org/pub/Download/FoswikiRelease02x01x11/Foswiki-2.1.11.tgz

ENV FOSWIKI_LATEST_SHA256 3a490eb460db4ca69d73dfe44c7984889552e5313eff60162760e80e66e5eba6

ENV FOSWIKI_LATEST Foswiki-2.1.11

RUN rm -rf /var/cache/apk/* && \
    rm -rf /tmp/* && \
    sed -n 's/main/testing/p' /etc/apk/repositories >> /etc/apk/repositories && \
    apk update && \
    apk upgrade && \
    apk add --update && \
    apk add ca-certificates imagemagick mailcap musl nginx openssl tzdata bash \
        db htmldoc make gcc db-dev musl-dev rcs \
        grep unzip wget zip perl perl-algorithm-diff perl-algorithm-diff-xs \
        perl-apache-logformat-compiler perl-archive-zip perl-authen-sasl \
        perl-authcas perl-cache-cache perl-cgi perl-cgi-session \
        perl-class-accessor perl-convert-pem perl-crypt-eksblowfish \
        perl-crypt-jwt perl-crypt-openssl-bignum perl-crypt-openssl-dsa \
        perl-crypt-openssl-random perl-crypt-openssl-rsa \
        perl-crypt-openssl-verify perl-crypt-openssl-x509 perl-crypt-passwdmd5 \
        perl-crypt-random perl-crypt-smime perl-crypt-x509 perl-dancer \
        perl-datetime perl-datetime-format-xsd perl-dbd-mysql perl-dbd-pg \
        perl-dbd-sqlite perl-dbi perl-crypt-sysrandom \
        perl-devel-overloadinfo perl-digest-perl-md5 perl-digest-sha1 \
        perl-email-mime perl-error perl-fcgi perl-fcgi-procmanager \
        perl-file-copy-recursive perl-file-remove perl-file-slurp perl-file-which \
        perl-filesys-notify-simple perl-file-which perl-gd perl-gssapi \
        perl-hash-merge-simple perl-hash-multivalue perl-html-tree \
        perl-image-info perl-io-socket-inet6 perl-json perl-json-xs \
        perl-ldap perl-libwww perl-locale-maketext-lexicon perl-locale-msgfmt \
        perl-lwp-protocol-https perl-mime-base64 perl-module-install \
        perl-module-pluggable perl-moo perl-moose perl-moosex \
        perl-moosex-types perl-moosex-types-common perl-locale-codes \
        perl-moosex-types-datetime perl-moosex-types-uri \
        perl-moox-types-mooselike perl-path-tiny perl-spreadsheet-parseexcel \
        perl-spreadsheet-xlsx perl-stream-buffered perl-sub-exporter-formethods \
        #perl-sereal perl-test-leaktrace perl-text-unidecode perl-text-soundex \
        perl-text-unidecode perl-text-soundex \
        perl-time-parsedate perl-type-tiny perl-uri perl-www-mechanize \
        perl-xml-easy perl-xml-enc perl-xml-generator perl-xml-parser \
        perl-xml-tidy perl-xml-writer perl-xml-xpath perl-yaml perl-yaml-tiny \
        perl-file-mmagic perl-file-mmagic-xs perl-net-saml2 imagemagick-perlmagick graphviz \
        odt2txt antiword lynx poppler-utils perl-email-address-xs perl-chi \
        perl-xml-sig iwatch perl-http-anyua perl-webservice-slack-webapi perl-dev  --update-cache && \
        # perl-libapreq2 -- Apache2::Request - Here for completeness but we use nginx \
    rm -fr /var/cache/apk/APKINDEX.* && \
    perl -MCPAN -e 'install BerkeleyDB,DB_File' && \
    perl -MCPAN -e "CPAN::Shell->notest('install', 'DB_File::Lock')" && \
    apk del make gcc musl-dev perl-dev db-dev && \
    touch /root/.bashrc && \
    wget ${FOSWIKI_LATEST_URL} && \
    echo "${FOSWIKI_LATEST_SHA256}  ${FOSWIKI_LATEST}.tgz" > ${FOSWIKI_LATEST}.tgz.sha256 && \
    sha256sum -cs ${FOSWIKI_LATEST}.tgz.sha256 && \
    mkdir -p /var/www && \
    mv ${FOSWIKI_LATEST}.tgz /var/www && \
    cd /var/www && \
    tar xvfz ${FOSWIKI_LATEST}.tgz && \
    rm -rf ${FOSWIKI_LATEST}.tgz && \
    mv ${FOSWIKI_LATEST} foswiki && \
    cd foswiki && \
    sh tools/fix_file_permissions.sh && \
    cd /var/www/foswiki && \
    tools/configure -save -noprompt && \
    tools/configure -save -set {DefaultUrlHost}='https://docker-foswiki.local' && \
    tools/configure -save -set {ScriptUrlPath}='/bin' && \
    tools/configure -save -set {ScriptUrlPaths}{view}='' && \
    tools/configure -save -set {PubUrlPath}='/pub' && \
    tools/configure -save -set {SafeEnvPath}='/bin:/usr/bin' && \
    tools/configure -save -set {PermittedRedirectHostUrls}='http://docker-foswiki.local:8765,https://docker-foswiki.local:8443' && \
    tools/extension_installer AttachContentPlugin -r -enable install && \
    tools/extension_installer AutoRedirectPlugin -r -enable install && \
    tools/extension_installer AutoTemplatePlugin -r -enable install && \
    tools/extension_installer BreadCrumbsPlugin -r -enable install && \
    tools/extension_installer NatSkin -r -enable install && \
    tools/extension_installer JQPhotoSwipeContrib -r -enable install && \
    tools/extension_installer CaptchaPlugin -r -enable install && \
    tools/extension_installer ClassificationPlugin -r -enable install && \
    tools/extension_installer CopyContrib -r -enable install && \
    tools/extension_installer DBCacheContrib -r -enable install && \
    tools/extension_installer DBCachePlugin -r -enable install && \
    tools/extension_installer DiffPlugin -r -enable install && \
    tools/extension_installer DigestPlugin -r -enable install && \
    tools/extension_installer DocumentViewerPlugin -r -enable install && \
    tools/extension_installer EditChapterPlugin -r -enable install && \
    tools/extension_installer FarscrollContrib -r -enable install && \
    tools/extension_installer FlexFormPlugin -r -enable install && \
    tools/extension_installer FlexWebListPlugin -r -enable install && \
    tools/extension_installer FilterPlugin -r -enable install && \
    tools/extension_installer GraphvizPlugin -r -enable install && \
    tools/extension_installer GridLayoutPlugin -r -enable install && \
    tools/extension_installer ImageGalleryPlugin -r -enable install && \
    tools/extension_installer ImagePlugin -r -enable install && \
    tools/extension_installer InfiniteScrollContrib -r -enable install && \
    tools/extension_installer JQAutoColorContrib -r -enable install && \
    tools/extension_installer JQDataTablesPlugin -r -enable install && \
    tools/extension_installer JQMomentContrib -r -enable install && \
    tools/extension_installer JQSelect2Contrib -r -enable install && \
    tools/extension_installer JQSerialPagerContrib -r -enable install && \
    tools/extension_installer JQTwistyContrib -r -enable install && \
    tools/extension_installer JSTreeContrib -r -enable install && \
    tools/extension_installer LdapContrib -r install && \
    tools/extension_installer LdapNgPlugin -r install && \
    tools/extension_installer LikePlugin -r -enable install && \
    tools/extension_installer ListyPlugin -r -enable install && \
    tools/extension_installer MediaElementPlugin -r -enable install && \
    tools/extension_installer NatSkinPlugin -r -enable install && \
    tools/extension_installer MetaCommentPlugin -r -enable install && \
    tools/extension_installer MetaDataPlugin -r -enable install && \
    tools/extension_installer MimeIconPlugin -r -enable install && \
    tools/extension_installer MoreFormfieldsPlugin -r -enable install && \
    tools/extension_installer MultiLingualPlugin -r -enable install && \
    tools/extension_installer OpenIDLoginContrib -r -enable install && \
    tools/extension_installer PageOptimizerPlugin -r -enable install && \
    tools/extension_installer PubLinkFixupPlugin -r -enable install && \
    tools/extension_installer NewUserPlugin -r -enable install && \
    tools/extension_installer RedDotPlugin -r -enable install && \
    tools/extension_installer RenderPlugin -r -enable install && \
    tools/extension_installer SamlLoginContrib -r -enable install && \
    tools/extension_installer SecurityHeadersPlugin -r -enable install && \
    tools/extension_installer StringifierContrib -r -enable install && \
    tools/extension_installer SolrPlugin -r -enable install && \
    tools/extension_installer TagCloudPlugin -r -enable install && \
    tools/extension_installer TopicInteractionPlugin -r -enable install && \
    tools/extension_installer TopicTitlePlugin -r -enable install && \
    tools/extension_installer WebLinkPlugin -r -enable install && \
    tools/extension_installer WebFontsContrib -r -enable install && \
    tools/extension_installer WorkflowPlugin -r -enable install && \
    tools/extension_installer XSendFileContrib -r -enable install && \
    tools/extension_installer GenPDFAddOn -r -enable install && \
    tools/configure -save -set {Plugins}{AutoViewTemplatePlugin}{Enabled}='0' && \
    tools/configure -save -set {Plugins}{LdapNgPlugin}{Enabled}='0' && \
    tools/configure -save -set {XSendFileContrib}{Header}='X-Accel-Redirect' && \
    tools/configure -save -set {XSendFileContrib}{Location}='/files' && \
    tools/configure -save -set  {PROXY}{UseForwardedHeaders}='1' && \
    rm -fr /var/www/foswiki/working/configure/download/* && \
    rm -fr /var/www/foswiki/working/configure/backup/* && \
    mkdir -p /run/nginx && \
    mkdir -p /etc/nginx/http.d && \
    chown -R nginx:nginx /var/www/foswiki

RUN apk update; \
    apk add git \
    db htmldoc make gcc db-dev musl-dev rcs && \
    cd /var/www/foswiki; \
    git clone https://github.com/timlegge/SamlLoginContrib.git && \
    cd SamlLoginContrib && \
    git checkout updates && \
    tar cvf ../SamlLoginContrib.tar * && \
    cd /var/www/foswiki && \
    tar xvf SamlLoginContrib.tar && \
    apk del --purge make musl-dev db-dev expat-dev openssl-dev \
        imagemagick-dev krb5-dev libxml2-dev gcc git perl-dev

# SP signing material.  {Saml}{sp_signing_*} and {Saml}{cacert} point into
# /var/www/foswiki/saml, which nothing else creates - without it the SP cannot
# sign the AuthnRequest or its own metadata.  Self-signed is fine for a dev
# container; mount real key material over this directory for anything else.
RUN mkdir -p /var/www/foswiki/saml && \
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout /var/www/foswiki/saml/sign.key \
        -out /var/www/foswiki/saml/sign.pem \
        -subj '/CN=docker-foswiki.local/O=Foswiki' && \
    cp /var/www/foswiki/saml/sign.pem /var/www/foswiki/saml/cacert.pem && \
    chown -R nginx:nginx /var/www/foswiki/saml && \
    chmod 600 /var/www/foswiki/saml/sign.key

RUN cd /var/www/foswiki && \
    tools/configure -save \
    `# --- authentication ------------------------------------------------` \
    -set "{LoginManager}=Foswiki::LoginManager::SamlLogin" \
    `# The IdP is the only authenticator; Foswiki must not keep passwords of` \
    `# its own.  It also has to be 'none' because mapUser calls addUser with an` \
    `# undef password on every login - with a password manager in place that` \
    `# throws 'User exists in the Password Manager' the second time round.` \
    -set "{PasswordManager}=none" \
    `# Must stay 1.  With 0, _isAlreadyMapped returns 0 unconditionally, so` \
    `# every login after the user topic exists re-enters the wikiname` \
    `# allocation loop and maps the same login to WikiName2, leaving the` \
    `# original user topic orphaned with empty form fields.` \
    -set "{Register}{AllowLoginName}=1" \
    -set "{Register}{EnableNewUserRegistration}=0" \
    `# --- rendering and indexing of the stored attributes ---------------` \
    `# The plugin half of SamlLoginContrib: supplies %SAML{...}% and` \
    `# %SAMLUSERS{...}%, and registers the Solr indexTopicHandler that puts the` \
    `# stored attributes into a user topic's Solr document even when they were` \
    `# never written into its UserForm.` \
    -set "{Plugins}{SamlLoginPlugin}{Enabled}=1" \
    -set "{Plugins}{SamlLoginPlugin}{Module}=Foswiki::Plugins::SamlLoginPlugin" \
    `# Keep each assertion's attributes in {WorkingDir}. This is the only way` \
    `# the *first* login's attributes can ever be shown - the user topic does` \
    `# not exist while the assertion is being consumed.` \
    -set "{Saml}{AttributeStore}=1" \
    `# SolrPlugin reindexes a topic as it is saved, renamed or attached to only` \
    `# if these are on; all three default to 0, which leaves a user topic out` \
    `# of Solr until the next full tools/solrjob run.  iwatch triggers that run` \
    `# on any data/*.txt write, so these only close the gap in between - but` \
    `# that gap is exactly the first login, when the user topic is created.` \
    -set "{SolrPlugin}{EnableOnSaveUpdates}=1" \
    -set "{SolrPlugin}{EnableOnRenameUpdates}=1" \
    -set "{SolrPlugin}{EnableOnUploadUpdates}=1" \
    `# --- user topic creation -------------------------------------------` \
    `# SamlLoginContrib never creates Main.<WikiName>; NewUserPlugin does, on` \
    `# the first page render after the callback has already redirected.  The` \
    `# image default is NewLdapUserTemplate, which is not what a SAML site` \
    `# wants.` \
    -set "{NewUserPlugin}{NewUserTemplate}=%SYSTEMWEB%.NewSamlUserTemplate" \
    `# --- SAML service provider -----------------------------------------` \
    -set "{Saml}{Debug}=1" \
    -set "{Saml}{issuer}=https://docker-foswiki.local" \
    -set "{Saml}{url}=https://docker-foswiki.local" \
    -set "{Saml}{metadata}=http://localhost/saml/metadata.xml" \
    -set "{Saml}{cacert}=/var/www/foswiki/saml/cacert.pem" \
    -set "{Saml}{sp_signing_cert}=/var/www/foswiki/saml/sign.pem" \
    -set "{Saml}{sp_signing_key}=/var/www/foswiki/saml/sign.key" \
    -set "{Saml}{sign_metatdata}=0" \
    -set "{Saml}{SupportSLO}=1" \
    `# --- assertion attribute mapping -----------------------------------` \
    `# The urn:oid names are the LDAP attributes as sent by an IdP using the` \
    `# SAML2 URI attribute name format: 2.5.4.42 givenName, 2.5.4.4 sn,` \
    `# 1.2.840.113549.1.9.1 mail.  These three must agree - WikiNameAttributes` \
    `# builds the WikiName, EmailAttributes finds the address, and AttributeMap` \
    `# fills the UserForm.  An unset or empty AttributeMap leaves every form` \
    `# field blank and says nothing about it in the log.` \
    -set "{Saml}{WikiNameAttributes}=urn:oid:2.5.4.42,urn:oid:2.5.4.4" \
    -set "{Saml}{EmailAttributes}=urn:oid:1.2.840.113549.1.9.1" \
    -set "{Saml}{AttributeMap}={ Email => q(urn:oid:1.2.840.113549.1.9.1), FirstName => q(urn:oid:2.5.4.42), LastName => q(urn:oid:2.5.4.4), OrganisationName => q(OrganisationName), Profession => q(Profession), Telephone => q(Telephone) }" \
    `# --- redirects ------------------------------------------------------` \
    `# The ACS URL and the issuer have to match what the IdP was registered` \
    `# with, so the host cannot be inferred from the request.` \
    -set "{DefaultUrlHost}=https://docker-foswiki.local" \
    -set "{ForceDefaultUrlHost}=1" \
    -set "{PermittedRedirectHostUrls}=https://docker-foswiki.local:8765,https://docker-foswiki.local:8443";

COPY nginx.default.conf /etc/nginx/http.d/default.conf
COPY docker-entrypoint.sh docker-entrypoint.sh
COPY iwatch.xml /etc/iwatch.xml

EXPOSE 80

CMD ["sh", "docker-entrypoint.sh"]
