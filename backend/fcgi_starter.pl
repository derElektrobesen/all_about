#!/usr/bin/perl

use strict;
use warnings;

use CGI;
use CGI::Fast;
use FCGI::ProcManager qw(pm_manage pm_pre_dispatch pm_post_dispatch);

use Sys::Syslog;
use POSIX;

use JSON;

my %params = (
    sock_path       => '/var/run/all_about.sock',
    port_used       => 0,
#    sock_path       => '127.0.0.1:9000',
    pid_path        => '/var/run/all_about.pid',
    need_root       => 1,
    n_processes     => 4,
    daemonize       => 0,
    username        => 'nobody',
    nginx_user      => 'http',
);

my %actions = (
    '/cgi-bin/login.cgi'        => {
        sub_ref         => \&login,
        content_type    => 'application/json',
    },
);

sub login {
    print to_json {ok=>1};
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
    unlink $params{sock_path};
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
    chown $uids{uid}, $uids{gid}, $params{sock_path};

    change_user if $params{daemonize};

    my $request = FCGI::Request(\*STDIN, \*STDOUT, \*STDERR, \%ENV, $socket, FCGI::FAIL_ACCEPT_ON_INTR)
        or die "Can't create request: $!\n";
    pm_manage( n_processes => $params{n_processes} );

    openlog("all_about", "ndelay,pid", "local0");
    reopen_std if $params{daemonize};

    while ($request->Accept() >= 0) {
        pm_pre_dispatch();
        if (my $ref = $actions{$ENV{SCRIPT_NAME}}) {
            print "Content-Type: $ref->{content_type}\r\n\r\n";
            $ref->{sub_ref}->();
        } else {
            print "Status: 404 Not Found\r\n\r\n";
        }
        pm_post_dispatch();
    }
    FCGI::CloseSocket($socket);
}

try_run;
init;
