package Cpanel::Services::Enabled;

# cpanel - Cpanel/Services/Enabled.pm              Copyright 2020 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

use Cpanel::cPStore::HostnameCert::DCV;
{
use experimental 'signatures';
package Cpanel::cPStore::HostnameCert::DCV;

sub _do_http_dcv_preflight ( $http_dcv_domains_ar, $http_filename, $http_contents, $output_obj ) { ## no critic qw(ManyArgs) - mis-parse
my @success_domains;

for my $domain ( sort { length $a <=> length $b } @$http_dcv_domains_ar ) {
$output_obj->out("$domain: Attempting HTTP DCV preflight check success!");

my $indent = $output_obj->create_indent_guard();

my $ok = eval {
Cpanel::Market::Provider::cPStore::Utils::imitate_http_dcv_check_locally(
$domain,
Cpanel::SSL::DCV::Ballot169::Constants::URI_DCV_RELATIVE_PATH() . "/$http_filename",
$http_contents,
);

1;
};

if ($ok) {
$output_obj->success("... success!");
push @success_domains, $domain;
}
else {
$output_obj->warn( Cpanel::Exception::get_string_no_id($@) );
}
}

return @success_domains;
}
}

=encoding utf-8

=cut

use Cpanel::LoadModule                ();
use Cpanel::Services::AlwaysInstalled ();

use constant _ENOENT => 2;

our $DOVECOT_CONF_FILE = '/var/cpanel/conf/dovecot/main';

# Cpanel::Config::Services::service_enabled

# a service use by default the file /etc/${service}disable
#   but some might use different flavors,
#   order matters as the first in a list, will be the filename used to enable the service
my %disable_files_exceptions = (
    'dns'        => '/etc/nameddisable',
    'ftp'        => [ '/etc/ftpddisable', '/etc/ftpserverdisable' ],
    'httpd'      => [qw{/etc/httpddisable /etc/apachedisable /etc/httpdisable}],
    'imap'       => [qw{/etc/imapdisable /etc/imapddisable /etc/cpimapdisable}],
    'mail'       => [qw{/etc/imapdisable /etc/imapddisable}],
    'pop'        => [qw{/etc/popdisable /etc/cppopdisable}],
    'postgresql' => [qw{/etc/postgresqldisable /etc/postgresdisable}],
    'rsyslogd'   => [qw{/etc/rsyslogddisable /etc/rsyslogdisable}],
    'tailwatchd' => [qw{/etc/tailwatchddisable /etc/tailwatchdisable}],
    'mysql'      => [qw{/etc/mysqldisable /etc/mysqlddisable}],
);

# psuedo-services that correlate to a service being provided by a specific implementation
my %installed_service_exceptions;
@installed_service_exceptions{ qw(dns ftp ftpd mail cpipv6), Cpanel::Services::AlwaysInstalled::SERVICES() } = ();

# exceptions:
#   mailman uses skipmailman in cpanel.config
my $services_status_from_cpanel_config = {

    # no need to manage the enable / disable logic for mailman
    #   this is already performed by Whostmgr::Services
    'mailman' => { key => 'skipmailman', meaning => 'disabled' },
};

=head1 FUNCTIONS

=head2 are_provided

Determines if a specified set of services are enabled

=over 2

=item Input

=over 3

=item C<SCALAR> or  C<HASHREF>

If the input is a C<SCALAR>, it is treated as a single service to check and this function's behavior is identical to C<is_provided>

If the input is a C<HASHREF>, it should be in the form of:

    { match: <any|all>, services: ["service1", "service2", … ] }

Where:

C<match> - (optional) Determines whether C<all> the services must be enabled, or C<any> of them. If not specified, it defaults to C<all>.

C<roles> - An C<ARRAYREF> of service names to check

=back

=item Output

=over 3

Returns 1 if the services are enabled, 0 otherwise

=back

=back

=cut

sub are_provided {
    my ($service) = @_;

    if ( 'HASH' eq ref $service ) {

        # Avoid altering the passed-in object.
        $service = { %$service, items => $service->{'services'} };

        delete $service->{services};
    }

    require Cpanel::Validate::AnyAllMatcher;
    return Cpanel::Validate::AnyAllMatcher::match( $service, \&is_provided );
}

=head2 is_provided($service)

Returns 1 if a service is provided
Returns 0 if a service is not provided

In this context we define provided as the service
being enabled or the service being configured as remote
and enabled.

=cut

sub is_provided {
    my ($service) = @_;
    my $is_enabled = is_enabled($service);
    if ( index( $service, 'mysql' ) == 0 && !$is_enabled ) {
        require Cpanel::GlobalCache;
        my $has_remote_mysql = Cpanel::GlobalCache::data( 'cpanel', 'has_remote_mysql' );

        # Since the global cache will not be built until upcp finishes
        # on v76 we need to fallback.  We can remove this check in v80+
        if ( !defined $has_remote_mysql ) {
            require Cpanel::MysqlUtils::MyCnf::Basic;
            $has_remote_mysql = Cpanel::MysqlUtils::MyCnf::Basic::is_remote_mysql();
        }

        # end removeable in v80
        return $has_remote_mysql;
    }
    return $is_enabled;
}

=head2 are_enabled

Determines if a specified set of services are enabled

=over 2

=item Input

=over 3

=item C<SCALAR> or  C<HASHREF>

If the input is a C<SCALAR>, it is treated as a single service to check and this function's behavior is identical to C<is_enabled>

If the input is a C<HASHREF>, it should be in the form of:

    { match: <any|all>, services: ["service1", "service2", … ] }

Where:

C<match> - (optional) Determines whether C<all> the services must be enabled, or C<any> of them. If not specified, it defaults to C<all>.

C<roles> - An C<ARRAYREF> of service names to check

=back

=item Output

=over 3

Returns 1 if the services are enabled, 0 otherwise

=back

=back

=cut

sub are_enabled {
    my ($service) = @_;

    if ( 'HASH' eq ref $service ) {

        # Avoid altering the passed-in object.
        $service = { %$service, items => $service->{'services'} };

        delete $service->{services};
    }

    require Cpanel::Validate::AnyAllMatcher;
    return Cpanel::Validate::AnyAllMatcher::match( $service, \&is_enabled );
}

# Returns 1 if service is enabled, 0 if disabled, -1 if unknown
sub is_enabled {
    my $service = shift;

    return -1 unless defined $service;

    if ( $service eq 'cpanalyticsd' ) {
        require Cpanel::Analytics::Enabled;
        return 'Cpanel::Analytics::Enabled'->can('is_enabled')->();
    }
    elsif ( $service eq 'cpgreylistd' ) {
        require Cpanel::GreyList::Config;
        return 'Cpanel::GreyList::Config'->can('is_enabled')->();
    }
    elsif ( $service eq 'cphulkd' ) {
        require Cpanel::Config::Hulk;
        return 'Cpanel::Config::Hulk'->can('is_enabled')->();
    }
    elsif ( $service eq 'imap' ) {
        return get_dovecot_enabled_protocols()->{'imap'} ? 1 : 0;
    }
    elsif ( $service eq 'pop' ) {
        return get_dovecot_enabled_protocols()->{'pop3'} ? 1 : 0;
    }
    elsif ( $service eq 'spamd' ) {
        return 0 unless is_enabled('exim');
    }
    elsif ( $service eq 'exim-altport' ) {
        require Cpanel::Services::List;
        return Cpanel::Services::List::canonicalize_service( $service, 1, {} )->{'enabled'};
    }
    elsif ( $service eq 'mysql' || $service eq 'mysqld' ) {
        $service = 'mysql';
    }
    elsif ( $service eq 'postgres' ) {
        $service = 'postgresql';
    }
    elsif ( $service eq 'cpdavd' ) {

        # Avoid require() in order to hide from perlpkg:
        Cpanel::LoadModule::load_perl_module('Cpanel::ServiceConfig::cpdavd');

        return 0 if !Cpanel::ServiceConfig::cpdavd::is_needed();
    }

    # exceptions: we cannot disable these services
    return 1 if ( $service eq 'dnsadmin' || $service eq 'cpsrvd' );

    if ( my $cpconfig_exception = $services_status_from_cpanel_config->{$service} ) {
        my $status = _process_service_status_from_cpconf(
            $service,
            $cpconfig_exception,
        );

        return $status if defined $status;
    }

    if ( !exists $installed_service_exceptions{$service} ) {

        # Make sure the service is actually installed before checking for a disabled file
        require Cpanel::Services::Installed;
        return 0 if !Cpanel::Services::Installed::service_is_installed($service);
    }

    if ( $service eq 'spamd' ) {
        require Cpanel::Services::Enabled::Spamd;
        return eval { Cpanel::Services::Enabled::Spamd::is_enabled() } // do {
            warn;
            1;    # this defaults to on for historical reasons
        };
    }

    return _check_for_disabled_file($service);
}

# Split out to satisfy code complexity metric.
sub _process_service_status_from_cpconf {
    my ( $service, $cpconfig_exception ) = @_;

    # lazy load to preserve minimal dependencies
    require Cpanel::Config::LoadCpConf;
    return -1 unless my $loadcpconf = 'Cpanel::Config::LoadCpConf'->can('loadcpconf_not_copy');
    my $cpconf = $loadcpconf->();
    my $value  = $cpconf->{ $cpconfig_exception->{'key'} };
    if ( $cpconfig_exception->{'meaning'} ) {
        if ( $cpconfig_exception->{'meaning'} eq 'disabled' ) {
            return !$value ? 1 : 0;
        }
        elsif ( $cpconfig_exception->{'meaning'} eq 'enabled' ) {
            return !!$value ? 1 : 0;
        }
    }

    # mailserver value is a string, so if it is configured, and it is set to 'disabled' then
    # it doesn't matter whether the disable files are set or not.
    if ( length $value ) {
        return 0 if $value eq 'disabled';
    }

    return undef;
}

sub _check_for_disabled_file {
    my $service = shift;

    if ( my $files = get_files_for_service($service) ) {
        foreach my $f (@$files) {
            return 0 if -e $f;

            # If the error was anything but ENOENT, that’s a system
            # misconfiguration that we should report.
            warn "stat($f): $!" if $! != _ENOENT();
        }

        # none of the potential files exist
        return 1;
    }

    # unknown
    return -1;
}

sub touch_disable_file {
    my $service = shift;
    return unless defined $service;

    # nothing to do anything if the service is already enabled
    return 1 if is_enabled($service) == 0;
    if ( $service eq 'cpgreylistd' ) {
        require Cpanel::GreyList::Config;
        return Cpanel::GreyList::Config::disable();
    }

    # If the service actually doesn't have these files, then nothing to do
    return 1 unless service_has_files($service);

    my $files = get_files_for_service($service);
    return unless defined $files && defined $files->[0];

    require Cpanel::FileUtils::TouchFile;
    return Cpanel::FileUtils::TouchFile::touchfile( $files->[0] );
}

sub remove_disable_files {
    my $service = shift;
    return unless defined $service;

    # If the service actually doesn't have these files, then nothing to do
    return 1 unless service_has_files($service);

    my $files = get_files_for_service($service);
    return unless defined $files;

    my $ok = 1;
    foreach my $f (@$files) {
        if ( -f $f && !-l $f ) {
            $ok = 0 if !unlink($f);
        }
    }

    return $ok;
}

sub service_has_files {
    my $service = shift;
    return unless defined $service;

    # service is not configured by files but by cpanel.config
    return if $service !~ m/^imap|pop$/ && exists $services_status_from_cpanel_config->{$service};
    return 1;
}

sub get_files_for_service {
    my $service = shift;
    return unless defined $service;

    return unless service_has_files($service);

    if ( !defined $disable_files_exceptions{$service} ) {

        # default behavior, the first file is the one use to enable the service
        return [ '/etc/' . $service . 'disable', '/etc/' . $service . 'isevil' ];
    }

    # normalize, to always return an array ref
    return ref $disable_files_exceptions{$service} ? $disable_files_exceptions{$service} : [ $disable_files_exceptions{$service} ];
}

sub get_dovecot_enabled_protocols {

    require Cpanel::LoadFile;
    require Cpanel::Dovecot::Constants;
    my $protos;
    local $@;
    eval {
        if ( -e $Cpanel::Dovecot::Constants::PROTOCOLS_FILE ) {

            # We have to keep the fallback to reading DOVECOT_CONF_FILE
            # until v66 since it won't be there on update in v64.
            $protos = Cpanel::LoadFile::load($Cpanel::Dovecot::Constants::PROTOCOLS_FILE);

        }
        else {
            # Ideally this would use AdvConfig, however its way to slow here
            # and we need to know what is enabled when we login to whm every time
            my $conf = Cpanel::LoadFile::load($DOVECOT_CONF_FILE);
            if ( length $conf ) {
                ($protos) = $conf =~ m{^protocols:[ \t]*([^\n]+)}m;
            }
        }
    };
    warn if $@ && !$ENV{'CPANEL_BASE_INSTALL'};

    $protos =~ s{[ \t]+$}{} if length $protos;
    $protos ||= 'imap pop3';

    return { map { $_ => 1 } split( m{ }, $protos ) };
}

1;
