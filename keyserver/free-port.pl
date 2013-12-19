# free-port.pl - Find a free TCP socket to bind to on the
# system. This program will output the port number that can be used
# for a TCP server or -1 if there's some error
#
# Copyright (c) 2012 CloudFlare, Inc.

use strict;
use warnings;

use IO::Socket::INET;

# This will create a socket listening for TCP connections on an
# available port number. By not passing the LocalPort option (or by
# passing in 0) the system chooses the port.

my $port = -1;
my $socket = IO::Socket::INET->new(Listen => 1, Proto => 'tcp');
if ( defined( $socket ) ) {
	$port = $socket->sockport();
	$socket->close()
}

print "$port\n";

