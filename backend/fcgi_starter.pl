#!/usr/bin/perl

use strict;
use warnings;

use CGI;
use CGI::Util qw( unescape );
use CGI::Fast;
use FCGI::ProcManager qw(pm_manage pm_pre_dispatch pm_post_dispatch);

use DBI;

use Sys::Syslog;
use POSIX;

use JSON;

my $server_name = "all_about";

my %params = (
    sock_path           => "/var/run/$server_name.sock",
    port_used           => 0,
    pid_path            => "/var/run/$server_name.pid",
    need_root           => 1,
    n_processes         => 1,
    daemonize           => 0,
    username            => 'nobody',
    nginx_user          => 'http',
    sql_user            => $server_name . '_user',
    sql_pass            => $server_name . '_password',
    sql_database_name   => $server_name,
    sql_database_host   => 'localhost',
    sql_database_port   => '3306',
);

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
    'bad_request'       => '400 Bad request',
    'anauthorized'      => '401 Unauthorized',
    'not_found'         => '404 Not found',
);

my %errors = (
    user_exists         => {
        err_code    => 1,
        err_text    => 'Username is already exists',
    },
    email_exists        => {
        err_code    => 2,
        err_text    => 'Email is already in use',
    },
);

my %sql_queries = (
    last_id             => {
        t           => 'select last_insert_id()',
    },
    add_user            => {
        t           => 'insert into users(username, password) values (?, MD5(?))',
    },
    add_user_info       => {
        t           => 'insert into users_info(user_id, name, surname, lastname, email) values (?, ?, ?, ?, ?)',
    },
);

sub _log {
    return syslog 'info', shift;
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

sub add_header { print "$_\r\n" for @_; }

sub login {
    my ($query, $params) = @_;
    return 'ok', to_json {
        ok => 1,
        hhh => undef,
    };
}

sub register {
    my ($query, $params, $dbh) = @_;
    my $err_ref;

    $dbh->begin_work;
    my $sth = prepare_sth('add_user', $dbh);
    my $count = $sth->execute($params->{username}, $params->{passw});
    $sth->finish;
    unless ($count) {
        $err_ref = $errors{user_exists};
    } else {
        $sth = prepare_sth('last_id', $dbh);
        $sth->execute;
        my $uid = $sth->fetchrow_arrayref()->[0];
        $sth->finish;

        $sth = prepare_sth('add_user_info', $dbh);
        $count = $sth->execute($uid, $params->{name}, $params->{surname} || undef,
            $params->{lastname} || undef, $params->{email});
        $err_ref = $errors{email_exists} unless $count;
        $sth->finish;
    }
    print to_json {
        ok          => defined $err_ref ? 0 : 1,
        err_code    => defined $err_ref ? $err_ref->{err_code} : 0,
        err_text    => defined $err_ref ? $err_ref->{err_text} : "Success",
    };
    defined $err_ref ? $dbh->rollback : $dbh->commit;
}

sub prepare_sth {
    my $name = shift;
    my $dbh = shift;
    my $sth_ref = $sql_queries{$name};
    my $sth = $sth_ref->{q};
    unless ($sth) {
        $sth = $dbh->prepare($sth_ref->{t});
        $sth_ref->{q} = $sth;
    }
    return $sth;
}

sub check_user {
    if ($params{need_root}) {
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

    if (-f $params{pid_path}) {
        open my $pidfile, '<', $params{pid_path};
        if ($pidfile) {
            my $pid = <$pidfile>;
            die "Already running with pid $pid\n" if kill 0, $pid;
        }
    }
    open my $pidfile, '>', $params{pid_path};
    print $pidfile $$;
    unlink $params{sock_path} unless $params{port_used};
}

sub get_uids {
    my $user = shift || $params{username};
    return (
        uid => scalar getpwnam $user,
        gid => scalar getgrnam $user
    );
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
    daemonize if $params{daemonize};

    my %uids = get_uids $params{nginx_user};
    my $socket = FCGI::OpenSocket($params{sock_path}, 10);
    chown $uids{uid}, $uids{gid}, $params{sock_path} unless $params{port_used};

    change_user if $params{daemonize};

    my $request = FCGI::Request(\*STDIN, \*STDOUT, \*STDERR, \%ENV, $socket, FCGI::FAIL_ACCEPT_ON_INTR)
        or die "Can't create request: $!\n";
    pm_manage( n_processes => $params{n_processes} );

    openlog("all_about", "ndelay,pid", "local0");
    reopen_std if $params{daemonize};

    my $dbh = DBI->connect("DBI:mysql:$params{sql_database_name}:" .
        "$params{sql_database_host}:$params{sql_database_port}", $params{sql_user}, $params{sql_pass},
        { RaiseError => 0, PrintError => 0, });
    die "Can't connect to DB: $!\n" unless $dbh;

    while ($request->Accept() >= 0) {
        pm_pre_dispatch();
        my $query = CGI->new;
        my ($status, $data, $ref) = ('not_found', undef, undef);
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
                ($status, $data) = $ref->{sub_ref}->($query, $params, $dbh);
            }
        }

        add_header "Status: $http_codes{$status}";
        add_header "Content-Type: " . $content_types{$ref->{content_type}} . "; charset=UTF-8" if defined $ref;
        print "\r\n"; # End of response headers

        print $data;

        pm_post_dispatch();
    }
    FCGI::CloseSocket($socket);
}

try_run;
init;
