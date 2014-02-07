#!/usr/bin/perl

use strict;
use warnings;

use CGI::Fast;
use FCGI::ProcManager qw(pm_manage pm_pre_dispatch pm_post_dispatch);

use Sys::Syslog;
use POSIX;


my %params = (
#    sock_path       => '/var/run/all_about.sock',
    sock_path       => '127.0.0.1:9000',
    pid_path        => '/var/run/all_about.pid',
    need_root       => 1,
    n_processes     => 4,
    daemonize       => 0,
);

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

sub process_request {
    my $req = shift;
    syslog("INFO", "Hello");
}

sub daemonize {
    fork && exit 0;
    setsid or die "Can't set sid: $!\n";
    chdir '/' or die "Cant change dir: $!\n";
    setgid(scalar getgrnam 'nobody') or die "Can't set gid: $!\n";
    setuid(scalar getpwnam 'nobody') or die "Can't set uid: $!\n";
}

sub reopen_std {
    open(STDIN,  "+>/dev/null") or die "Can't open STDIN: $!";
    open(STDOUT, "+>&STDIN") or die "Can't open STDOUT: $!";
    open(STDERR, "+>&STDIN") or die "Can't open STDERR: $!";
}

sub init {
    daemonize if $params{daeminize};
    my $socket = FCGI::OpenSocket($params{sock_path}, 10);
    my $request = FCGI::Request(\*STDIN, \*STDOUT, \*STDERR, \%ENV, $socket, FCGI::FAIL_ACCEPT_ON_INTR)
        or die "Can't create request: $!\n";
    pm_manage( n_processes => $params{n_processes} );

    openlog("All About FCGI server", "ndelay,pid", "local0");
    reopen_std if $params{daemonize};

    while ($request->Accept() >= 0) {
        print "Content-Type: application/json\r\n\r\n";
        pm_pre_dispatch();
        print '{"ok":1}';
        process_request($request);
        pm_post_dispatch();
    }
    FCGI::CloseSocket($socket);
}

try_run;
init;
