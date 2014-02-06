#!/usr/bin/perl

use strict;
use warnings;

use CGI::Fast;
use FCGI::ProcManager qw(pm_manage pm_pre_dispatch pm_post_dispatch);

use Sys::Syslog;

use POSIX;

my %params = (
    sock_path       => '/var/run/all_about.sock',
    n_processes     => 4,
    daemonize       => 0,
);

sub process_request {
    my $req = shift;
    syslog("INFO", "Hello");
    print "Jello\n";
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
    my $socket = FCGI::OpenSocket($params{sock_path}, 10);

    daemonize if $params{daeminize};

    my $request = FCGI::Request(\*STDIN, \*STDOUT, \*STDERR, \%ENV, $socket)
        or die "Can't create request: $!\n";
    pm_manage(n_processes => $params{n_processes});
    openlog("All About FCGI server", "ndelay,pid", "local0");

    reopen_std if $params{daemonize};

    while ($request->Accept() >= 0) {
        pm_pre_dispatch();
        process_request($request);
        pm_post_dispatch();
    }
    FCGI::CloseSocket($socket);
}

init;
