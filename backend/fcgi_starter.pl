#!/usr/bin/perl

use strict;
use warnings;

package ErrHandler;

use Tie::StdHandle;
use strict;

our @ISA = 'Tie::StdHandle';

sub TIEHANDLE {
    my ($class, @args) = @_;
    my $self = $class->SUPER::TIEHANDLE;
    ${*$self}{sub} = $args[0];
    return $self;
}

sub WRITE {
    my $self = shift;
    my $subroutine = ${*$self}{sub};
    $subroutine->($_[0]) if defined $subroutine;
}

1;

package main;

use Sys::Syslog qw( :standard :macros );
use Getopt::Std;
use Pod::Usage;

use CGI;
use CGI::Util qw( unescape );
use CGI::Fast;
use FCGI::ProcManager qw( pm_manage pm_pre_dispatch pm_post_dispatch );
use Digest::MD5 qw( md5_hex );

use DBI;
use POSIX;
use JSON;

our $VERSION = '1.0';
sub HELP_MESSAGE() { pod2usage(1) and exit 0; }
sub VERSION_MESSAGE() { print STDERR "$0 v.$VERSION\n"; }

our %global_parametrs;

sub update_default_global_parametrs {
    my $srv_name = shift;
    %global_parametrs = (
        server_name         => $srv_name,
        sock_path           => "/var/run/$srv_name.sock",
        pid_path            => "/var/run/$srv_name.pid",
        need_root           => 1,
        n_processes         => 4,
        daemonize           => 0,
        username            => 'nobody',
        nginx_user          => 'nobody',
        db_user             => '',
        db_pass             => '',
        db_name             => '',
        db_host             => 'localhost',
        db_port             => '3306',
        log_level           => 1,
        max_queries         => 30,
        log_params          => {},
        @_,
    );
}

sub read_config {
    my $cfg_path = shift;
    my %params_types = (
        server_name  => 'scalar',
        sock_path    => 'scalar',
        nginx_user   => 'scalar',
        n_processes  => 'scalar',

        db_name      => 'scalar',
        db_user      => 'scalar',
        db_pass      => 'scalar',
        db_host      => 'scalar',
        db_port      => 'scalar',

        log_level    => 'scalar',
        log_params   => 'lmap',
    );

    die "Can't open '$cfg_path': not found\n" unless -f $cfg_path;

    open my $f, '<', $cfg_path;

    my (%params, $server_name);
    while (<$f>) {
        chomp;
        next if $_ =~ /^\s*$/;

        if (/^\s*([^\s]+)\s*=\s*(.*)/) {
            my ($key, $val) = (lc($1), $2);
            unless (defined $params_types{$key}) {
                print STDERR "Unknown config file option found: '$key'\n";
                next;
            }

            $val =~ s/\s*$//;
            if ($key eq 'server_name') {
                $server_name = $val;
            } elsif ($params_types{$key} eq 'scalar') {
                $params{$key} = $val;
            } elsif ($params_types{$key} eq 'list') {
                $params{$key} = [ split /[,\s]+/, $val ];
            } elsif ($params_types{$key} eq 'lmap') {
                $params{$key} = { map { $_ => 1 } split /[,\s]+/, $val };
            }
        } else {
            print STDERR "Unknown config file option line found: '$_'\n";
        }
    }
    return ($server_name, %params);
}

sub parse_cmd_line_args {
    getopts("hc:d", \my %args);

    pod2usage(1) and exit 0 if defined $args{h}; # Show help message and exit

    my @cfg = qw( SimpleServer ); # First arg is server name
    @cfg = read_config($args{c}) if defined $args{c};
    update_default_global_parametrs(@cfg);

    $global_parametrs{daemonize} = defined $args{d}; # Daemonization
}

sub __log {
    my ($log_level, $type, $msg) = @_; # TODO: Show call point line number
    syslog($type, $msg) if $log_level <= $global_parametrs{log_level};
}

sub _log  { __log($_[0], LOG_INFO,      $_[1]); }
sub _warn { __log(0,     LOG_WARNING,   $_[0]); }
sub _err  { __log(0,     LOG_ERR,       $_[0]); }

my %content_types = (
    json            => 'application/json',
    plain           => 'text/plain',
);

my %actions = (
    '/cgi-bin/login.cgi'        => {
        sub_ref         => \&login,
        content_type    => 'json',
        required_fields => [qw( login passw remember )],
    },
    '/cgi-bin/register.cgi'     => {
        sub_ref         => \&register,
        content_type    => 'json',
        required_fields => [qw( username email name passw )],
    },
);

my %http_codes = (
    'ok'                => '200 Ok',
    'err'               => '500 Internal Error',
    'bad_request'       => '400 Bad Request',
    'unauthorized'      => '401 Unauthorized',
    'not_found'         => '404 Not Found',
    'user_exists'       => '409 Conflict',
);

my %sql_queries = ();

sub sql_exec {
    my ($dbh, $query, @params) = @_;

    my $sth = prepare_sth($query, $dbh);
    my $count = $sth->execute(@params);

    $count = 0 if !defined($count) || uc($count) eq "0E0";

    return ($sth, $count);
}

sub get_uri_params {
    return undef unless exists $ENV{QUERY_STRING};

    my %result;
    if ($ENV{QUERY_STRING} =~ /=/) {
        my(@pairs) = split(/[&;]/, $ENV{QUERY_STRING});
        my($param, $value);
        for (@pairs) {
            ($param, $value) = split '=', $_, 2;
            $param = unescape($param);
            $value = unescape($value);
            $result{$param} = $value;
        }
    }

    return wantarray ? %result : \%result;
}

sub is_logged_in {
    # TODO
}

sub check_session {
    my ($query, $dbh, $uid) = @_;

    unless (defined $uid) {
        $uid = $query->cookie(-name => 'session');
    }

    my ($sth, $count) = sql_exec($dbh, 'select id, time, session_id from sessions where user_id = ? and host = ? and ip = ?',
        $uid, $query->remote_host, $query->remote_addr);

    my %result = ( session_expired => 1 );

    if ($count) {
        ($result{session_id}, $result{creation_time}, my $session_s_id) = $sth->fetchrow_array;
        _log(3, "Session_id: $result{session_id}, creation_time: $result{creation_time}, str_s_id: $session_s_id");
    }

    $sth->finish;
    return %result;
}

sub create_session {
    my ($query, $dbh, %params) = @_;

    my %session = check_session($query, $dbh, $params{uid});
    my $sth;

    unless (defined $params{login}) {
        ($sth, my $count) = sql_exec($dbh, 'select username from users where id = ?', $params{uid});
        if ($count) {
            $params{login} = $sth->fetchrow_arrayref()->[0];
        } else {
            $params{login} = "";
            _err("Login not found for id $params{uid}");
        }
        $sth->finish;

        unless ($params{login}) {
            _warn("Login for $params{uid} uid is empty");
            return undef;
        }
    }

    my $host = $query->remote_host;
    my $addr = $query->remote_addr;

    my $session_s_id = sprintf "$params{login}:$host:$addr:%s:%f", time, rand 100500;
    $session_s_id = md5_hex($session_s_id);

    if (defined $session{session_id}) {
        ($sth) = sql_exec($dbh, 'update sessions set session_id = ?, time = CURRENT_TIMESTAMP where id = ?',
            $session_s_id, $session{session_id});
    } else {
        ($sth) = sql_exec($dbh, 'insert into sessions(user_id, host, ip, session_id) values (?, ?, ?, ?)', $params{uid}, $host, $addr, $session_s_id);
    }

    $sth->finish;

    return create_session_cookie(uid => $params{uid}, sid => $session_s_id, save_session => $params{remember});
}

sub create_session_cookie {
    my %params = @_;

    my %cookie_params = ( -secure => 1 );
    if ($params{save_session}) {
        $cookie_params{'-expires'} = '+30d';
    }

    my $u_c = CGI::cookie(
        -name       => 'userid',
        -value      => $params{uid} || 0,
        %cookie_params,
    );

    my $s_c = CGI::cookie(
        -name       => 'session',
        -value      => $params{sid} || 0,
        %cookie_params,
    );

    return [$u_c, $s_c];
}

sub login {
    my ($query, $params, $dbh) = @_;

    my $status = 'unauthorized';
    my $data = { ok => 0 };

    my ($sth, $count) = sql_exec($dbh, 'select id from users where username = ? and password = MD5(?)', $params->{login}, $params->{passw});

    my $cookie = create_session_cookie(save_session => $params->{remember});

    if ($count) {
        my $uid = $sth->fetchrow_arrayref()->[0];
        $sth->finish;

        ($sth, $count) = sql_exec($dbh, 'select u.username, ui.name, ui.surname, ui.lastname, ui.email ' .
            'from users u join users_info ui on u.id = ui.user_id where u.id = ?', $uid);

        if ($count) {
            my ($login, $name, $surname, $lastname, $email) = $sth->fetchrow_array;
            $data = { login => $login, name => $name, surname => $surname,
                lastname => $lastname, email => $email, err_code => 0, };
            $cookie = create_session($query, $dbh, uid => $uid, remember => $params->{remember});
            $status = 'ok';
        } else {
            $cookie = create_session_cookie(save_session => $params->{remember}, uid => $uid);
        }
    }

    $sth->finish;
    return $status, $cookie, to_json $data;
}

sub register {
    my ($query, $params, $dbh) = @_;
    my $err_ref;

    $dbh->begin_work;
    my ($sth, $count) = sql_exec($dbh, 'insert into users(username, password) values (?, MD5(?))',
        $params->{username}, $params->{passw});
    $sth->finish;

    my $cookie;
    my $status = 'user_exists';
    if ($count) {
        ($sth) = sql_exec($dbh, 'select last_insert_id()');
        my $uid = $sth->fetchrow_arrayref()->[0];
        $sth->finish;

        ($sth, $count) = sql_exec($dbh, 'insert into users_info(user_id, name, surname, lastname, email) values (?, ?, ?, ?, ?)',
            $uid, $params->{name}, $params->{surname} || undef,
            $params->{lastname} || undef, $params->{email});
        $sth->finish;

        if ($count) {
            # Insert was ok
            $status = 'ok';
            $cookie = create_session($query, $dbh, uid => $uid);
            $dbh->commit;
        } else {
            $dbh->rollback;
        }
    }
    return $status, $cookie, '';
}

sub prepare_sth {
    my $query = shift;
    my $dbh = shift;
    my $sth_ref = $sql_queries{$query};
    my $sth = $sth_ref->{sth};
    unless ($sth) {
        _log(1, "Preparing sql query '$query'") if $global_parametrs{log_params}->{sql};
        $sth = $dbh->prepare($query);
        $sth_ref->{sth} = $sth;
    }

    $sth_ref->{t} = localtime;

    if (scalar(keys %sql_queries) > $global_parametrs{max_queries}) {
        my $to_delete = undef;
        my $time = undef;
        for my $q (keys %sql_queries) {
            if (!defined($to_delete) || $time > $sql_queries{$q}->{t}) {
                $time = $sql_queries{$q}->{t};
                $to_delete = $q;
            }
        }
        delete $sql_queries{$to_delete} if defined $to_delete;
    }

    return $sth;
}

sub check_user {
    if ($global_parametrs{need_root}) {
        my $root_id = getpwnam 'root';
        my $user_id = getpwnam $ENV{USER};
        if ($root_id != $user_id) {
            $! = EPERM;     # Permission denied
            die "Error: $!\n";
        }
    }
}

sub try_run {
    check_user;

    if (-f $global_parametrs{pid_path}) {
        open my $pidfile, '<', $global_parametrs{pid_path};
        if ($pidfile) {
            my $pid = <$pidfile>;
            die "Already running with pid $pid\n" if kill 0, $pid;
        }
    }
    open my $pidfile, '>', $global_parametrs{pid_path};
    print $pidfile $$;
    unlink $global_parametrs{sock_path};
}

sub get_uids {
    my $user = shift || $global_parametrs{username};
    my $uid = scalar getpwnam $user or die "Can't get uid of user '$user': $!";
    my $gid = scalar getgrnam $user or die "Can't get gid of user '$user': $!";
    return ( uid => $uid, gid => $gid );
}

sub change_user {
    my %uids = get_uids;
    setgid $uids{gid} or die "Can't set gid: $!\n";
    setuid $uids{uid} or die "Can't set uid: $!\n";
}

sub daemonize {
    fork && exit 0;
    setsid or die "Can't set sid: $!\n";
    chdir '/' or die "Cant change dir: $!\n";
}

sub reopen_std {
    open(STDIN,  "+>/dev/null") or die "Can't open STDIN: $!";
    open(STDOUT, "+>&STDIN") or die "Can't open STDOUT: $!";
    open(STDERR, "+>&STDIN") or die "Can't open STDERR: $!";
}

sub init {
    {
        my $dbh = DBI->connect("DBI:mysql:$global_parametrs{db_name}:" .
            "$global_parametrs{db_host}:$global_parametrs{db_port}", $global_parametrs{db_user}, $global_parametrs{db_pass},
            { RaiseError => 0, PrintError => 1, });
        die "Can't connect to DB.\n" unless $dbh;
    }

    daemonize if $global_parametrs{daemonize};

    my %uids = get_uids $global_parametrs{nginx_user};
    my $socket = FCGI::OpenSocket($global_parametrs{sock_path}, 10);
    chown $uids{uid}, $uids{gid}, $global_parametrs{sock_path};

    change_user if $global_parametrs{daemonize};

    sub log_errors {
        my $msg = shift;
        my $sub = $msg =~ /^FastCGI:/ ? \&_warn : \&_err;
        $sub->($msg);
    };

    tie *STDERR, 'ErrHandler', \&log_errors;
    openlog($global_parametrs{server_name}, "ndelay,pid,cons", LOG_USER);

    my $request = FCGI::Request(\*STDIN, \*STDOUT, \*STDERR, \%ENV, $socket, FCGI::FAIL_ACCEPT_ON_INTR)
        or die "Can't create request: $!\n";
    pm_manage( n_processes => $global_parametrs{n_processes} );

    reopen_std if $global_parametrs{daemonize};

    my $dbh = DBI->connect("DBI:mysql:$global_parametrs{db_name}:" .
        "$global_parametrs{db_host}:$global_parametrs{db_port}", $global_parametrs{db_user}, $global_parametrs{db_pass},
        { RaiseError => 0, PrintError => 0, });
    die "Can't connect to DB: $!\n" unless $dbh;

    while ($request->Accept() >= 0) {
        pm_pre_dispatch();
        my $query = CGI->new;
        my ($status, $data, $ref, $cookie) = ('not_found', undef, undef, undef);
        if ($ref = $actions{$ENV{SCRIPT_NAME}}) {
            my $params = get_uri_params;
            my $flag = 1;
            for (@{$ref->{required_fields}}) {
                unless (defined $params->{$_}) {
                    $status = 'bad_request';
                    $flag = 0;
                    last;
                }
            }
            if ($flag) {
                ($status, $cookie, $data) = $ref->{sub_ref}->($query, $params, $dbh);
            }
        }

        unless (defined $http_codes{$status}) {
            _err("Unknown http code key found: '$status'");
            $status = 'err';
            $ref = $data = undef;
        }

        print CGI::header(
            -type => $content_types{$ref->{content_type}},
            -nph => 1,
            -status => $http_codes{$status},
            -expires => '+30d',
            -cookie => $cookie,
            -charset => 'utf-8',
        );

        print $data if defined $data;

        pm_post_dispatch();
    }
    FCGI::CloseSocket($socket);
}

parse_cmd_line_args;
try_run;
init;

__END__

=head1 NAME

fcgi_starter.pl -- Simple FCGI server.

=head1 OPTIONS

=over 8

=item B<-c>

Set config file path. If not submitted, default config parametrs will be used.

=item B<-d>

Daemonize on start. All log messges will be printed in syslog.

=item B<--help>

Print a brief message and exit.

=item B<--version>

Print script version and exit.

=back

=head1 CONFIGURE FILE OPTIONS

In this section all configure file options will be explained.
If no information about a type of option value given, assume scalar (number or string) without quotes.

=over 8

=item B<server_name>

Set FCGI server name. Default is SimpleServer.

=item B<n_processes>

Set FCGI process manager workers count. Default is 4.

=item B<sock_path>

Set FCGI socket path. Default is /var/run/_server_name_.sock.
_server_name_ will be taken from B<server_name> option.

=item B<nginx_user>

Set nginx user name. For a socket permissions is needed [default: nobody].

=item B<db_name>

Set database name. Default value is an empty field.

=item B<db_user>

Set database user name. Default value is an empty field.

=item B<db_pass>

Set database user password. Default value is an empty field.

=item B<db_host>

Set database server hostname. localhost is default.

=item B<db_port>

Set database port number. 3306 is default.

=item B<log_level>

Set log level [1..5].
All messages will be sent in syslog.

=item B<log_params>

A comma-splitted list of extra logging features.
Available features:
[ sql ]

=back

=head1 DESCRIPTION

B<This program> will start a simple FCGI server.

=cut
