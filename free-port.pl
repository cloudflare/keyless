#!/usr/bin/perl
#
# free-port.pl - Find a free TCP socket to bind to on the
# system. This program will output the port number that can be used
# for a TCP server or -1 if there's some error
#
# Copyright (c) 2012 CloudFlare, Inc.

use strict;
use warnings;

use Getopt::Std;

# This will create a socket listening for TCP connections on an
# available port number. By not passing the LocalPort option (or by
# passing in 0) the system chooses the port.
#
# Script takes one optional argument: -6 which performs the test using IPv6
# space (vs. IPv4)

my %options=();
getopts("6", \%options);

my $socket;
if ($options{6}) {
    require IO::Socket::INET6;
    $socket = IO::Socket::INET6->new(Listen => 1, Proto => 'tcp');
} else {
    require IO::Socket::INET;
    $socket = IO::Socket::INET->new(Listen => 1, Proto => 'tcp');
}

my $port = -1;
if ( defined( $socket ) ) {
    $port = $socket->sockport();
    $socket->close()
}

print "$port\n";
