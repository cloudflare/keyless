#!/usr/bin/perl
# free-port.pl - Find a free TCP socket to bind to on the
# system. This program will output the port number that can be used
# for a TCP server or -1 if there's some error
#
# Copyright (c) 2012 CloudFlare, Inc.

use strict;
use warnings;

use IO::Socket::INET;
use IO::Socket::INET6;
use Getopt::Std;

# This will create a socket listening for TCP connections on an
# available port number. By not passing the LocalPort option (or by
# passing in 0) the system chooses the port.

my %options=();
getopts("6", \%options);
my $port = -1;
my $use_ipv6 = 0;
$use_ipv6 = 1 if ( $options{6} );
my $socket;
if ( $use_ipv6 > 0 ) {
        $socket = IO::Socket::INET6->new(Listen => 1, Proto => 'tcp');
} else {
        $socket = IO::Socket::INET->new(Listen => 1, Proto => 'tcp');
}
if ( defined( $socket ) ) {
        $port = $socket->sockport();
        $socket->close()
}

print "$port\n";
