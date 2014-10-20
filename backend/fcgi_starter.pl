#!/usr/bin/perl

use strict;
use warnings;

use Sys::Syslog qw( :standard :macros );

use CGI;
use CGI::Util qw( unescape );
use CGI::Fast;
use FCGI::ProcManager qw( pm_manage pm_pre_dispatch pm_post_dispatch );
use Digest::MD5 qw( md5_hex );

use DBI;
use POSIX;
use JSON;

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
    log_level           => 5,
    log_params          => { sql => 1, },
    max_queries         => 3,
);

sub __log {
    my ($log_level, $type, $msg) = @_; # TODO: Show call point line number
    syslog($type, $msg) if $log_level <= $params{log_level};
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

sub add_header { print "$_\r\n" for @_; }

sub is_logged_in {

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
    my ($query, $dbh, $uid, $login) = @_;

    my %session = check_session($query, $dbh);
    my $sth;

    unless (defined $login) {
        ($sth, my $count) = sql_exec($dbh, 'select username from users where id = ?', $uid);
        if ($count) {
            $login = $sth->fetchrow_arrayref()->[0];
        } else {
            $login = "";
            _warn("Login not found for id $uid");
        }
        $sth->finish;
    }

    my $host = $query->remote_host;
    my $addr = $query->remote_addr;

    my $session_s_id = sprintf "$login:$host:$addr:%s:%f", scalar localtime, rand 100500;
    $session_s_id = md5_hex($session_s_id);

    if (defined $session{session_id}) {
        ($sth) = sql_exec($dbh, 'update sessions set session_id = ?, time = CURRENT_TIMESTAMP where id = ?',
            $session_s_id, $session{session_id});
    } else {
        ($sth) = sql_exec($dbh, 'insert into sessions(user_id, host, ip, session_id) values (?, ?, ?, ?)', $uid, $host, $addr, $session_s_id);
    }

    $sth->finish;

    return create_session_cookie($uid, $session_s_id);
}

sub create_session_cookie {
    my ($userid, $session_id) = @_;
    my $u_c = cookie(
        -name       => 'userid',
        -expires    => '+30d',
        -value      => $userid || 0,
        -secure     => 1,
    );

    my $s_c = cookie(
        -name       => 'session',
        -expires    => '+30d',
        -value      => $session_id || 0,
        -sequre     => 1,
    );

    return [$u_c, $s_c];
}

sub login {
    my ($query, $params, $dbh) = @_;

    my $status = 'unauthorized';
    my $data = { ok => 0 };

    my ($sth, $count) = sql_exec($dbh, 'select id from users where username = ? and password = MD5(?)', $params->{login}, $params->{passw});

    my $cookie = create_session_cookie;

    if ($count) {
        my $uid = $sth->fetchrow_arrayref()->[0];
        $sth->finish;

        ($sth, $count) = sql_exec($dbh, 'select u.username, ui.name, ui.surname, ui.lastname, ui.email ' .
            'from users u join users_info ui on u.id = ui.user_id where u.id = ?', $uid);

        if ($count) {
            my ($login, $name, $surname, $lastname, $email) = $sth->fetchrow_array;
            $data = { login => $login, name => $name, surname => $surname,
                lastname => $lastname, email => $email, err_code => 0, };
            $cookie = create_session($query, $dbh, $uid);
            $status = 'ok';
        } else {
            $cookie = create_session_cookie $uid;
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

    unless ($count) {
        $err_ref = $errors{user_exists};
    } else {
        ($sth) = sql_exec($dbh, 'select last_insert_id()');
        my $uid = $sth->fetchrow_arrayref()->[0];
        $sth->finish;

        ($sth, $count) = sql_exec($dbh, 'insert into users_info(user_id, name, surname, lastname, email) values (?, ?, ?, ?, ?)',
            $uid, $params->{name}, $params->{surname} || undef,
            $params->{lastname} || undef, $params->{email});

        $err_ref = $errors{email_exists} unless $count;
        $sth->finish;
    }
    print to_json {
        err_code    => defined $err_ref ? $err_ref->{err_code} : 0,
        err_text    => defined $err_ref ? $err_ref->{err_text} : "Success",
    };
    defined $err_ref ? $dbh->rollback : $dbh->commit;
}

sub prepare_sth {
    my $query = shift;
    my $dbh = shift;
    my $sth_ref = $sql_queries{$query};
    my $sth = $sth_ref->{sth};
    unless ($sth) {
        _log(1, "Preparing sql query '$query'") if $params{log_params}->{sql};
        $sth = $dbh->prepare($query);
        $sth_ref->{sth} = $sth;
    }

    $sth_ref->{t} = localtime;

    if (scalar(keys %sql_queries) > $params{max_queries}) {
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

    sub log_errors {
        my $msg = shift;
        if ($msg =~ /^FastCGI:/) {
            _warn($msg);
        } else {
            _err($msg);
        }
    };

    tie *STDERR, 'ErrHandler', \&log_errors;
    openlog($server_name, "ndelay,pid,cons", LOG_USER);

    my $request = FCGI::Request(\*STDIN, \*STDOUT, \*STDERR, \%ENV, $socket, FCGI::FAIL_ACCEPT_ON_INTR)
        or die "Can't create request: $!\n";
    pm_manage( n_processes => $params{n_processes} );

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

        unless (defined $http_codes{$status}) {
            _err("Unknown http code key found: '$status'");
            $status = 'err';
            $ref = $data = undef;
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
