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

use MIME::Base64;

use DBI;
use POSIX;
use JSON;
use JSON::Parse qw(parse_json);
use HTTP::Request;

use LWP::UserAgent;

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
        extra_sql_log       => 1,
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
        session_expire_time => 30 * 24 * 60 * 60,           # 30 days
        auth_token_expire_time      => 10 * 60,             # 10 minutes
        access_token_expire_time    => 24 * 60 * 60,        # 24 hours
        refresh_token_expire_time   => 30 * 24 * 60 * 60,   # 30 days
        log_params          => {},
        accept_origin       => [],
        login_page          => '',
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

        login_page   => 'scalar',

        accept_origin=> 'list',
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
    my ($log_level, $type, $msg, @args) = @_; # TODO: Show call point line number

    # TODO: REMOVE ME
    $type = LOG_WARNING;

    $msg = sprintf $msg, @args if scalar @args;
    syslog($type, $msg) if $log_level <= $global_parametrs{log_level};
}

sub _log  { my $lvl = shift;
            __log($lvl,  LOG_INFO,      @_); }
sub _warn { __log(0,     LOG_WARNING,   @_); }
sub _err  { __log(0,     LOG_ERR,       @_); }

my %content_types = (
    json            => 'application/json',
    plain           => 'text/plain',
);

my %actions = (
    '/cgi-bin/login.cgi'            => {
        sub_ref         => \&login,
        content_type    => 'json',
        required_fields => [qw( login passw remember )],
        need_login      => 0,
    },
    '/cgi-bin/register.cgi'         => {
        sub_ref         => \&register,
        content_type    => 'json',
        required_fields => [qw( username email name passw )],
        need_login      => 0,
    },
    '/cgi-bin/get_users_info.cgi'    => {
        sub_ref         => \&get_info_about_all_users,
        content_type    => 'json',
    },
    '/cgi-bin/get_user_info.cgi'    => {
        sub_ref         => \&get_info_about_user,
        required_fields => [qw( username )],
        content_type    => 'json',
        need_login      => 1,
    },
    '/cgi-bin/logout.cgi'           => {
        sub_ref         => \&logout,
        need_login      => 1,
    },
    '/cgi-bin/send_msg.cgi'         => {
        sub_ref         => \&send_msg,
        need_login      => 1,
        content_type    => 'json',
        required_fields => [qw( msg to )],
    },
    '/cgi-bin/check_messages.cgi'   => {
        sub_ref         => \&check_messages,
        need_login      => 1,
        content_type    => 'json',
    },
    '/cgi-bin/oauth_request_auth_token.cgi'     => {
        sub_ref         => \&request_oauth_auth_token,
        content_type    => 'html',
        required_fields => [qw( response_type client_id redirect_uri )],
    },
    '/cgi-bin/oauth_oauth_login.cgi'   => {
        sub_ref         => \&oauth_try_login,
        content_type    => 'json',
        required_fields => [qw( grant_type client_id )],
    },
    '/cgi-bin/oauth_verify_token.cgi'  => {
        sub_ref         => \&oauth_verify_token,
        content_type    => 'json',
        required_fields => [qw( client_id grant_type code redirect_uri client_secret )],
    },
    '/cgi-bin/oauth_request_access_token.cgi'   => {
        sub_ref         => \&request_oauth_access_token,
        content_type    => 'json',
        required_fields => [qw( grant_type code )],
    },
    '/cgi-bin/oauth_refresh_auth_token.cgi' => {
        sub_ref         => \&refresh_oauth_token,
        content_type    => 'json',
        required_fields => [qw( grant_type refresh_token client_secret )],
    },
    '/cgi-bin/yammer_auth.cgi' => {
        sub_ref         => \&yammer_auth,
        content_type    => 'json',
    },
    '/cgi-bin/save_yammer_token.cgi' => {
        sub_ref         => \&save_yammer_token,
    },
    '/cgi-bin/get_yammer_data.cgi' => {
        sub_ref         => \&get_yammer_data,
        content_type    => 'json',
    },
);

my %http_codes = (
    'ok'                => '200 Ok',
    'found'             => '302 Found',
    'err'               => '500 Internal Error',
    'bad_request'       => '400 Bad Request',
    'unauthorized'      => '401 Unauthorized',
    'not_found'         => '404 Not Found',
    'user_exists'       => '409 Conflict',
);

my %sql_queries = ();

sub sql_exec {
    my ($dbh, $query, @params) = @_;

    my $sth = prepare_sth($query, $dbh, @params);
    my $count = $sth->execute(@params);

    $count = 0 if !defined($count) || uc($count) eq "0E0";

    return ($sth, $count);
}

sub get_request_params {
    my $query = shift;
    my $env = shift;
    my %result;

    if (defined $env->{QUERY_STRING}) {
        if ($env->{QUERY_STRING} =~ /=/) {
            my(@pairs) = split(/[&;]/, $env->{QUERY_STRING});
            my($param, $value);
            for (@pairs) {
                ($param, $value) = split '=', $_, 2;
                $param = unescape($param);
                $value = unescape($value);
                $result{$param} = $value;
            }
        }
    }

    if (my $post_params_ptr = $query->Vars) {
        grep { $result{$_} = $post_params_ptr->{$_} } keys %$post_params_ptr;
    }

    return wantarray ? %result : \%result;
}

sub check_session {
    my ($query, $dbh) = @_;

    my %r = ( expired => 1 );
    my $session_id = $query->cookie('session');
    return %r unless $session_id; # No session in cookie

    my ($sth, $count) = sql_exec($dbh, 'select id, user_id, UNIX_TIMESTAMP(time), ' .
        'host, ip from sessions where session_id = ?', $session_id);
    return %r unless $count; # No session in db

    my ($id, $uid, $time, $host, $ip) = $sth->fetchrow_array();
    $sth->finish;

    return %r if $host ne $query->remote_host || $ip ne $query->remote_addr; # Other PC

    if ($time + $global_parametrs{session_expire_time} <= time()) {
        sql_exec($dbh, "delete from sessions where session_id = ?", $session_id);
        return %r;
    }

    return ( uid => $uid, session_id => $session_id, id => $id );
}

sub create_session {
    my ($query, $dbh, %params) = @_;

    my %session = check_session($query, $dbh);
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

    if (defined $session{id}) {
        ($sth) = sql_exec($dbh, 'update sessions set session_id = ?, time = CURRENT_TIMESTAMP where id = ?',
            $session_s_id, $session{id});
    } else {
        ($sth) = sql_exec($dbh, 'insert into sessions(user_id, host, ip, session_id) values (?, ?, ?, ?)', $params{uid}, $host, $addr, $session_s_id);
    }

    $sth->finish;

    return create_session_cookie(uid => $params{uid}, sid => $session_s_id, save_session => $params{remember});
}

sub create_session_cookie {
    my %params = @_;

    my %cookie_params = ( -secure => 0 );
    if ($params{save_session}) {
        $cookie_params{'-expires'} = '+30d';
    }

    my $s_c = CGI::cookie(
        -name       => 'session',
        -value      => $params{sid} || "",
        %cookie_params,
    );

    return [ $s_c ];
}

sub get_user_info {
    my ($uid, $dbh) = @_;

    my ($sth, $count) = sql_exec($dbh, 'select u.username, ui.name, ui.surname, ui.lastname, ui.email ' .
            'from users u join users_info ui on u.id = ui.user_id where u.id = ?', $uid);

    my %r;
    if ($count) {
        ($r{login}, $r{name}, $r{surname}, $r{lastname}, $r{email}) = $sth->fetchrow_array();
    }
    return %r;
}

sub request_oauth_auth_token {
    my ($query, $params, $dbh) = @_;

    my %data = ();
    if (uc($params->{response_type}) ne 'CODE') {
        %data = ( error => 'invalid request', error_description => 'unknown response_type found' );
    }

    my ($sth, $count) = sql_exec($dbh, "select id, redirect_uri from oauth_clients where value = ?", $params->{client_id});
    unless ($count) {
        %data = ( error => 'invalid client', error_description => 'malformed client_id' );
    }

    my $content = "<html><head><h1>Error: %s</h1></head><body>%s</body></html>";

    return 'bad_request', undef, sprintf($content, $data{error}, $data{error_description}) if scalar keys %data;

    my ($client_id, $redir_uri) = $sth->fetchrow_array();
    $sth->finish();

    if ($redir_uri ne $params->{redirect_uri}) {
        return 'unauthorized', undef, sprintf($content, 'access denied', 'invalid redirect uri');
    }

    _log(3, "Request token for '%s' client_id [$client_id]", $params->{client_id}, $client_id);

    my $key = md5_hex("$client_id" . time . rand 100500);
    (undef, $count) = sql_exec($dbh, "insert into tokens(type, token, client_id, redir_url, state) " .
        "values ('auth_token', ?, ?, ?, ?)", $key, $client_id, $params->{redirect_uri} || "", $params->{state} || "");

    return 'err', undef, sprintf($content, 'internal error', 'database error') unless $count;

    my $state = defined $params->{state} ? "&state=$params->{state}" : "";
    my $redir_url = "https://$global_parametrs{server_name}/login?oauth=true&client_id=$key";
    _log(5, "Auth key = $key");

    open my $f, '<', $global_parametrs{login_page} or _warn("Can't open login page: '$global_parametrs{login_page}'");
    local $/ = undef;

    $content = <$f>;
    $content = sprintf $content, $key;
    return 'ok', undef, $content;
}

sub check_access_token {
    my ($dbh, $access_token) = @_;
    my ($sth, $count) = sql_exec($dbh, 'select type, UNIX_TIMESTAMP(time), user_id from tokens where token = ?', $access_token);
    return undef unless $count;

    my ($token_type, $create_time, $uid) = $sth->fetchrow_array();
    return undef unless $token_type eq 'access_token';

    if ($create_time + $global_parametrs{access_token_expire_time} < time) {
        _log(1, "Token $access_token is expired");
        drop_token($dbh, $access_token);
        return undef;
    }

    return { uid => $uid };
}

sub drop_token {
    my ($dbh, $token) = @_;
    sql_exec($dbh, 'delete from tokens where token = ?', $token);
}

sub oauth_verify_token {
    my ($query, $params, $dbh) = @_;

    if (uc $params->{grant_type} ne 'AUTHORIZATION_CODE') {
        return 'bad_request', undef, to_json {
            error => 'bad_request',
            error_description => 'invalid grant type',
        };
    }

    my ($sth, $count) = sql_exec($dbh, "select UNIX_TIMESTAMP(t.time), c.value, t.state, t.user_id, c.redirect_uri, c.client_secret, c.id " .
        " from tokens t join oauth_clients c on c.id = t.client_id where t.token = ?", $params->{code});
    return 'unauthorized', undef, to_json {
        error => 'access_denied',
        error_description => 'invalid code',
    } unless $count;

    my ($time, $client_id, $state, $uid, $redir_uri, $client_secret, $cl_id) = $sth->fetchrow_array();

    drop_token($dbh, $params->{code});
    if ($time + $global_parametrs{auth_token_expire_time} <= time()) {
        return 'unauthorized', undef, to_json {
            error => 'access_denied',
            error_description => 'token expired'
        };
    }

    if (($client_id ne $params->{client_id}) || ($client_secret ne $params->{client_secret})) {
        return 'unauthorized', undef, to_json {
            error => 'access_denied',
            error_description => 'invalid client id'
        };
    }

    if ($redir_uri ne $params->{redirect_uri}) {
        return 'unauthorized', undef, to_json {
            error => 'access_denied',
            error_description => 'invalid redirect uri'
        };
    }

    my $key = md5_hex("$client_id$params->{code}" . time . rand 100500);
    my $refresh_key = md5_hex("$params->{code}$client_id" . time . rand 100500);
    (undef, $count) = sql_exec($dbh, "insert into tokens(type, token, user_id, client_id) " .
        "values ('access_token', ?, ?, ?), ('refresh_token', ?, ?, ?)", $key, $uid, $cl_id, $refresh_key, $uid, $cl_id);

    return 'err', undef, to_json { error => 'unknown_error', error_description => 'internal error' } unless $count;

    my $response_data = {
        token_type => 'basic',
        access_token => $key,
        expires_in => $global_parametrs{access_token_expire_time},
        refresh_token => $refresh_key,
    };

    if ($redir_uri) {
        $response_data->{redirect_to} = $redir_uri;
    }

    return 'ok', undef, to_json $response_data;
}

sub oauth_try_login {
    my ($query, $params, $dbh) = @_;

    my ($sth, $count) = sql_exec($dbh, "select t.client_id, t.state, c.redirect_uri, UNIX_TIMESTAMP(t.time) " .
        "from tokens t join oauth_clients c on c.id = t.client_id where t.token = ?", $params->{client_id});

    return 'unauthorized', undef, to_json {
        error => 'access_denied',
        error_description => 'invalid auth token'
    } unless $count;

    my ($client_id, $state, $url, $time) = $sth->fetchrow_array();

    if ($time + $global_parametrs{auth_token_expire_time} <= time()) {
        drop_token($dbh, $params->{code});
        return 'unauthorized', undef, to_json {
            error => 'access_denied',
            error_description => 'auth token expired'
        };
    }

    my $auth_header_data = $query->http('Authorization');

    $auth_header_data =~ s/Basic //i;
    my $decoded_credentials = decode_base64($auth_header_data);

    $decoded_credentials =~ /([^:]+):(.+)/;
    my ($user, $pass) = ($1, $2);

    my $uid = real_login($dbh, $user, $pass);
    return 'unauthorized', undef, to_json {
        error => 'access_denied',
        error_description => 'Invalid username or password'
    } if $uid == -1;

    drop_token($dbh, $params->{client_id});

    my $key = md5_hex("$client_id$params->{client_id}" . time . rand 100500);
    sql_exec($dbh, "insert into tokens(client_id, state, token, user_id, type) values " .
        "(?, ?, ?, ?, 'access_token')", $client_id, $state, $key, $uid);

    return 'ok', undef, to_json { redirect_to => "$url?code=$key" };
}

sub request_oauth_access_token {
    my ($query, $params, $dbh) = @_;

    my ($sth, $count) = sql_exec($dbh, "select UNIX_TIMESTAMP(time), redir_url, client_id from tokens where token = ?", $params->{code});

    return 'unauthorized', undef, to_json {
        error => 'access_denied',
        error_description => 'invalid auth token'
    } unless $count;

    my ($time, $url, $client_id) = $sth->fetchrow_array();
    $sth->finish();

    if ($time + $global_parametrs{auth_token_expire_time} <= time()) {
        drop_token($dbh, $params->{code});
        return 'unauthorized', undef, to_json {
            error => 'access_denied',
            error_description => 'auth token expired'
        } unless $count;
    }

    my $auth_header_data = $query->http('Authorization');

    $auth_header_data =~ s/Basic //i;
    my $decoded_credentials = decode_base64($auth_header_data);

    $decoded_credentials =~ /([^:]+):(.+)/;
    my ($user, $pass) = ($1, $2);

    my $uid = real_login($dbh, $user, $pass);
    return 'unauthorized' if $uid == -1;

    drop_token($dbh, $params->{code});

    my $key = md5_hex("$client_id$params->{code}" . time . rand 100500);
    my $refresh_key = md5_hex("$params->{code}$client_id" . time . rand 100500);
    (undef, $count) = sql_exec($dbh, "insert into tokens(type, token, user_id, client_id) " .
        "values ('access_token', ?, ?, ?), ('refresh_token', ?, ?, ?)", $key, $uid, $client_id, $refresh_key, $uid, $client_id);

    return 'err', undef, to_json { error => 'unknown_error', error_description => 'internal error' } unless $count;

    my $response_data = {
        token_type => 'basic',
        access_token => $key,
        expires_in => $global_parametrs{access_token_expire_time},
        refresh_token => $refresh_key,
    };

    if ($url) {
        $response_data->{redirect_to} = $url;
    }

    return 'ok', undef, to_json $response_data;
}

sub refresh_oauth_token {
    my ($query, $params, $dbh) = @_; # TODO
    my ($sth, $count) = sql_exec($dbh, "select type, UNIX_TIMESTAMP(time), user_id, client_id from tokens where token = ?",
        $params->{refresh_token});

    return 'unauthorized' unless $count;

    my ($type, $time, $uid, $cl_id) = $sth->fetchrow_array();

    return 'unauthorized' unless $type eq 'refresh_token';

    if ($time + $global_parametrs{refresh_token_expire_time} < time) {
        _log(1, "Refresh token $params->{refresh_token} is expired");
        sql_exec($dbh, "delete from tokens where user_id = ? and client_id = ?", $uid, $cl_id);
        return 'unauthorized';
    }

    sql_exec($dbh, "delete from tokens where where user_id = ? and client_id = ?", $uid, $cl_id);
    my $key = md5_hex("$params->{refresh_token}$cl_id" . time . rand 100500);
    my $refresh_key = md5_hex("$params->{code}$cl_id" . time . rand 100500);

    (undef, $count) = sql_exec($dbh, "insert into tokens(type, token, user_id, client_id) " .
        "values ('access_token', ?, ?, ?), ('refresh_token', ?, ?, ?)", $key, $uid, $cl_id, $refresh_key, $uid, $cl_id);

    return 'err', undef, to_json { error => 'unknown_error', error_description => 'internal error' } unless $count;

    my $response_data = {
        token_type => 'basic',
        access_token => $key,
        expires_in => $global_parametrs{access_token_expire_time},
        refresh_token => $refresh_key,
    };

    return 'ok', undef, to_json $response_data;
}

sub get_info_about_all_users {
    my ($query, $params, $dbh) = @_;

    my ($sth, $count) = sql_exec($dbh, 'select u.id, u.username, ui.name, ui.surname, ui.lastname, ui.email ' .
            'from users u join users_info ui on u.id = ui.user_id order by u.username');

    my $data = { logged_in => defined $params->{'-uid'} ? 1 : 0 };

    if (!$count) {
        $data = { error => 'No users found' };
    }

    while (my ($uid, $username, $name, $surname, $lastname, $email) = $sth->fetchrow_array()) {
        my %me = ();
        if (defined $params->{'-uid'}) {
            %me = ( surname => $surname, lastname => $lastname, email => $email, );
            $me{me} = 1 if $uid == $params->{'-uid'};
        }
        push @{$data->{data}}, { username => $username, name => $name, %me };
    }

    return 'ok', undef, to_json $data;
}

sub get_info_about_user {
    my ($query, $params, $dbh) = @_;
    my ($sth, $count) = sql_exec($dbh, "select id from users where username = ?", $params->{username});
    unless ($count) {
        return 'ok', undef, to_json { error => "User $params->{username} not found" };
    }

    my $uid = $sth->fetchrow_arrayref()->[0];
    my %data = get_user_info($uid, $dbh);
    return 'ok', undef, to_json \%data;
}

sub fetch_user_info {
    my ($uid, $dbh, $query, $remember) = @_;

    my ($sth, $count) = sql_exec($dbh, 'select u.username, ui.name, ui.surname, ui.lastname, ui.email ' .
            'from users u join users_info ui on u.id = ui.user_id where u.id = ?', $uid);

    my %data = get_user_info($uid, $dbh);

    my $cookie;
    if (%data) {
        $data{err_code} = 0;
        $cookie = create_session($query, $dbh, uid => $uid, remember => $remember);
    } else {
        $cookie = create_session_cookie(save_session => $remember, uid => $uid);
    }

    return ($cookie, \%data);
}

sub logout {
    my ($query, $params, $dbh) = @_;
    my $sid = $query->cookie('session');

    sql_exec($dbh, "delete from sessions where session_id = ?", $sid);
    return ('ok', create_session_cookie);
}

sub real_login {
    my ($dbh, $login, $pass) = @_;

    my ($sth, $count) = sql_exec($dbh, 'select id from users where username = ? and password = MD5(?)', $login, $pass);

    my $uid = -1;
    if ($count) {
        $uid = $sth->fetchrow_arrayref()->[0];
    }

    $sth->finish();
    return $uid;
}

sub login {
    my ($query, $params, $dbh) = @_;

    my %session = check_session($query, $dbh);

    if (defined $session{uid}) {
        my %info = get_user_info($session{uid}, $dbh);
        if ($info{login} eq $params->{login}) {
            return 'ok', undef, to_json \%info;
        } else {
            sql_exec($dbh, "delete from sessions where id = ?", $session{id});
        }
    }

    my $status = 'unauthorized';
    my $data = {};

    my $uid = real_login($dbh, $params->{login}, $params->{passw});
    my $cookie = create_session_cookie(save_session => $params->{remember});

    if ($uid >= 0) {
        ($cookie, $data) = fetch_user_info($uid, $dbh, $query, $params->{remember});
        $status = 'ok' if scalar %$data;
    }
    return $status, $cookie, to_json $data;
}

sub send_msg {
    my ($query, $params, $dbh) = @_;

    sub ret_err { return 'ok', undef, to_json { err_test => shift }; }

    unless (length $params->{msg}) {
        return ret_err 'Message is too short';
    }

    if (length($params->{msg}) > 255) {
        return ret_err 'Message is to long (maximum length is 255 symbols)';
    }

    my ($sth, $count) = sql_exec($dbh, "select id from users where username = ?", $params->{to});
    unless ($count) {
        return ret_err 'Destination user was not found';
    }

    my $dest_uid = $sth->fetchrow_arrayref()->[0];
    $sth->finish;

    if ($dest_uid == $params->{'-uid'}) {
        return ret_err "You can't send message to yourself";
    }

    sql_exec($dbh, "insert into messages(message, id_from, id_to) values (?, ?, ?)",
        $params->{msg}, $params->{'-uid'}, $dest_uid);

    return 'ok', undef, to_json { 'ok' => 1 };
}

sub check_messages {
    my ($query, $params, $dbh) = @_;

    my $req = <<'END';
select
    m.id,
    m.message,
    m.time,
    m.read,
    u_from.username,
    u_to.username,
    u_from.id = ?
from messages m
join users u_from on u_from.id = m.id_from
join users u_to on u_to.id = m.id_to
where m.id > ?
order by m.id
END

    my ($sth, $count) = sql_exec($dbh, $req,
        $params->{'-uid'}, $params->{last_id} || 0);

    my $last_id = -1;
    my @data;
    my $tmp = {};
    while ((my $l_id,
            $tmp->{msg},
            $tmp->{time},
            $tmp->{read},
            $tmp->{from},
            $tmp->{to},
            $tmp->{from_me}) = $sth->fetchrow_array) {
        push @data, $tmp;
        $tmp = {};
        $last_id = $l_id;
    }

    ($sth, undef) = sql_exec($dbh, "select username from users where id != ? order by username", $params->{"-uid"});

    return 'ok', undef, to_json { data => \@data, last_id => $last_id,
        users => [ map { $_->[0] } @{$sth->fetchall_arrayref()} ] };
};

sub register {
    my ($query, $params, $dbh) = @_;
    my $err_ref;

    $params->{username} =~ s/^\s*(.*)\s*$/$1/;

    my $ret_err = sub {
        my ($field, $text) = @_;
        return 'bad_request', undef, to_json({ error => "Incorrect $field format" . (defined $text ? ": $text" : "") });
    };

    for (qw( username passw name surname lastname email )) {
        return $ret_err->($_, 'field is empty') unless length $params->{$_};
    }
    return $ret_err->('username', 'spaces are prohibited') if $params->{username} =~ /\s/;
    return $ret_err->('username', "':' character is prohibited") if $params->{username} =~ /:/;
    return $ret_err->('email') unless $params->{email} =~ /^[\w.\d]+@[\w.\d]+$/; # TODO: Fix email mask

    $dbh->begin_work;
    my ($sth, $count) = sql_exec($dbh, 'insert into users(username, password) values (?, MD5(?))',
        $params->{username}, $params->{passw});
    $sth->finish;

    my $cookie;
    my $status = 'user_exists';
    my $data = { error => 'User already exists' };
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
            ($cookie, $data) = fetch_user_info($uid, $dbh, $query, 1);
            $dbh->commit;
        } else {
            $data = { error => 'Email is already registered' };
            $dbh->rollback;
        }
    }
    return $status, $cookie, to_json $data;
}

sub check_yammer_key {
    my ($dbh, $key) = @_;

    my ($sth, $count) = sql_exec($dbh, "select token from yammer_tokens where user_key = ?", $key);
    return $count > 0;
}

sub yammer_auth {
    my ($query, $params, $dbh) = @_;

    my $key = md5_hex(time . rand 100500);

    my $cookie = CGI::cookie(
        -name       => 'yammer_key',
        -value      => $key,
    );

    my (undef, $count) = sql_exec($dbh, "insert into yammer_tokens(user_key) values (?)", $key);

    unless ($count) {
        _warn("Can't insert $key user key in db");
        return 'err';
    }

    return 'ok', $cookie, to_json({
        redirect_to => "https://www.yammer.com/dialog/oauth?" .
            "client_id=lm6kWM4iuMsjdsMVLeUTYg&redirect_uri=https%3A%2F%2Fallabout%2Foauth_result%3Fscope%3D$key"
    });
}

sub save_yammer_token {
    my ($query, $params, $dbh) = @_;

    return 'err' unless defined $params->{scope};

    my $user_key = $params->{scope};

    unless (check_yammer_key($dbh, $user_key)) {
        _warn("Can't find scoped key $user_key from request");
        return 'err';
    }

    my ($sth, $count) = sql_exec($dbh, "select id from yammer_tokens where user_key = ?", $user_key);

    unless ($count) {
        _warn("Scoped key $user_key not found in db");
        return 'err';
    }

    my $id = $sth->fetchrow_arrayref()->[0];

    my $ua = LWP::UserAgent->new;
    my $response = $ua->get('https://www.yammer.com/oauth2/access_token.json?client_id=lm6kWM4iuMsjdsMVLeUTYg&' .
            "client_secret=HjcePE2pGrUOVgn57ZfD70fo1KcvT03DrCFxVPqYA&code=$params->{code}");

    if ($response->is_success) {
        $response = parse_json($response->decoded_content);

        sql_exec($dbh, "update yammer_tokens set token = ? where id = ?", $response->{access_token}->{token}, $id);

        return 'found', undef, undef, { -location => '/#yammer_data' };
    }

    return 'err';
}

sub get_yammer_data {
    my ($query, $params, $dbh) = @_;

    unless (check_yammer_key($dbh, $query->cookie('yammer_key'))) {
        return 'unauthorized', CGI::cookie(-name => 'yammer_key', -value => '');
    }

    my ($sth, undef) = sql_exec($dbh, "select token from yammer_tokens where user_key = ?", $query->cookie("yammer_key"));
    my $token = $sth->fetchrow_arrayref()->[0];


    my $ua = LWP::UserAgent->new;
    my $req = HTTP::Request->new('GET' => "https://www.yammer.com/api/v1/messages/following.json");
    $req->header('Authorization' => "Bearer $token");

    my $response = $ua->request($req);

    if ($response->is_success) {
        return 'ok', undef, $response->decoded_content;
    }

    return 'err';
}

sub prepare_sth {
    my $query = shift;
    my $dbh = shift;
    my $sth_ref = $sql_queries{$query};
    my $sth = $sth_ref->{sth};

    $query =~ s/\s+/ /mg;
    _log(1, "Preparing sql query '$query'") if $global_parametrs{log_params}->{sql};
    _log(1, "Sql params: [" . join(', ', @_) . "]") if $global_parametrs{extra_sql_log};

    unless ($sth) {
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

    pm_manage( n_processes => $global_parametrs{n_processes} );
    my $request = FCGI::Request(\*STDIN, \*STDOUT, \*STDERR, \%ENV, $socket, FCGI::FAIL_ACCEPT_ON_INTR)
        or die "Can't create request: $!\n";

    reopen_std if $global_parametrs{daemonize};

    my $dbh = DBI->connect("DBI:mysql:$global_parametrs{db_name}:" .
        "$global_parametrs{db_host}:$global_parametrs{db_port}", $global_parametrs{db_user}, $global_parametrs{db_pass},
        { RaiseError => 0, PrintError => 0, });
    die "Can't connect to DB: $!\n" unless $dbh;

    while ($request->Accept() >= 0) {
        pm_pre_dispatch();
        my $query = CGI->new;
        my ($status, $data, $ref, $cookie) = ('not_found', undef, undef, undef);

        my $env = $request->GetEnvironment();
        use Data::Dumper;
        open my $f, '>', '/tmp/stuff';
        print $f Dumper $env;

        if ($ref = $actions{$env->{SCRIPT_NAME}}) {
            my $params = get_request_params $query, $env;
            my $flag = 1;

            my $access_token = $query->http('Authorization');
            if (defined $access_token && $access_token =~ /^\s*Bearer\s(\w+)\s*$/i) {
                $access_token = $1;
            } else {
                $access_token = undef;
            }

            if (defined $global_parametrs{log_params}->{query}) {
                my $query_str = "Request: ";
                $query_str .= join ', ', map { "[$_: $env->{$_}]" } qw( SCRIPT_NAME ); # for debug features

                # TODO: Mask 'password' request field
                $query_str .= " [REQUEST_PARAMS: " . join(', ', map { "{ $_: $params->{$_} }" } keys %$params) . ']';
                $query_str .= " [ACCESS_TOKEN: " . $access_token . "]" if $access_token;
                _log(1, $query_str);
            }

            if (defined $global_parametrs{log_params}->{cookie}) {
                _log(1, "[COOKIES: " . join(', ',
                        map { "{ $_, " . ($query->cookie($_) || '') . " }" } $query->cookie()) . ']');
            }

            for (@{$ref->{required_fields}}) {
                unless (defined $params->{$_}) {
                    _warn("Required field '$_' not found in request params");
                    $status = 'bad_request';
                    $data = to_json {error => 'invalid_request', error_desription => "param $_ is required"};
                    $flag = 0;
                    last;
                }
            }

            my $access_granted = 0;
            if ($flag && $access_token) {
                my $r = check_access_token($dbh, $access_token);
                if ($r) {
                    $access_granted = 1;
                    $params->{'-uid'} = $r->{uid};
                }
            }

            my %r = check_session($query, $dbh);
            $params->{'-uid'} = $r{uid};

            if (!$access_granted && $flag && $ref->{need_login}) {
                if ($r{expired}) {
                    $status = "unauthorized";
                    $flag = 0;
                    $cookie = create_session_cookie; # This will delete cookie
                    delete $params->{'-uid'};
                }
            }

            my $request_origin = $query->http('Origin');
            if ($request_origin) {
                unless (grep { $request_origin eq lc } @{$global_parametrs{accept_origin}}) {
                    # Origin is not accepted
                    warn("Origin '$request_origin' is not allowed");
                    $status = "unauthorized";
                    $flag = 0;
                    $request_origin = undef;
                } elsif (my $need_return = $query->http('Access-Control-Request-Headers')) {
                    # Preflight request came: need return 200 & wait new request
                    $flag = 0;
                    $status = 'ok';
                }
            } else {
                $request_origin = undef;
            }

            my $extra_headers = {};
            if ($flag) {
                ($status, $cookie, $data, $extra_headers) = $ref->{sub_ref}->($query, $params, $dbh);
            }

            if (defined $status) {
                # No data will be returned if status is not defined
                unless (defined $http_codes{$status}) {
                    _err("Unknown http code key found: '$status'");
                    $status = 'err';
                    $ref = $data = undef;
                }

                if (defined $global_parametrs{log_params}->{response}) {
                    _log(1, "Response: [Status: $http_codes{$status}], [Data: " . ($data || "") . "]");
                }

                $extra_headers = {} unless defined $extra_headers;
                my $response = CGI::header(
                    -type => $content_types{$ref->{content_type}},
                    -nph => 1,
                    -status => $http_codes{$status},
                    -expires => '+30d',
                    -cookie => $cookie,
                    -access_control_allow_origin => $request_origin,
                    -accept => '*',
                    -charset => 'utf-8',
                    -access_control_allow_headers => 'Content-Type, X-Requested-With, Authorization',
                    -access_control_allow_methods => 'GET,POST,OPTIONS',
                    -access_control_allow_credentials => 'true',
                    %{$global_parametrs{default_response_headers}},
                    %{$extra_headers},
                );

                $data = '' unless defined $data;
                print "$response$data";
            }
        } else {
            _warn("Requested script not found on server: '$env->{SCRIPT_NAME}'");
            print CGI::header( -status => $http_codes{not_found} );
        }

        $request->Flush();
        $request->Finish();
        $request->LastCall(); # XXX: REMOVE ME
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

A comma-separated list of extra logging features.
Available features:

=over 16

=item I<cookie>

Log request cookies list

=item I<sql>

Log all sql requests

=item I<query>

Log all http(s) requests

=item I<response>

Log response results

=back

=back

=head1 DESCRIPTION

B<This program> will start a simple FCGI server.

=cut
