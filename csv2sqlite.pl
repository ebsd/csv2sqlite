#!/usr/bin/perl

# Use a 2 column CSV file to import hosts informations to Sqlite DB
# I needed this to identify smb1 flow between hosts
# Flow are captured by a suricata rule
# Suricata log to graylog
# CSV come from Graylog

# CSV contain 2 column
# IP DEST | IP SRC

# Before inserting a couple of hosts, a SELECT check if this couple aleady exist in DB

use DBI;
#use strict;

my $driver   = "SQLite"; 
my $database = "/home/ebsd/Documents/clients-smb1.sqlite";
my $dsn = "DBI:$driver:dbname=$database";
my $userid = "";
my $password = "";
my $dbh = DBI->connect($dsn, $userid, $password, { RaiseError => 1 }) 
   or die $DBI::errstr;

print "Opened database successfully\n";


# [Create DB] Avec contrainte unicité sur le couple ip src et ip dst

#my $stmt = qq(CREATE TABLE SMB1
#   (src_ip	TEXT,
#	dest_ip	TEXT,
#	src_host TEXT,
#	dest_host TEXT,
#	src_os	TEXT,
#	dst_os TEXT,
#	UNIQUE(src_ip,dest_ip)    
#););

#my $rv = $dbh->do($stmt);
#if($rv < 0) {
#   print $DBI::errstr;
#} else {
#   print "Table created successfully\n";
#}
#$dbh->disconnect();

# [/Create DB]

exclude_ip="10.15.15.1"

while (<>) {
	/([^,]+),([^,]+)/;
	$a=$1; $b=$2;

	if ($a != $exclude_ip) {


		$host1=`host $b`; $host1 =~ s/.* //; $host1 =~ s/\.$//; chomp $host1;
		$host2=`host $a`; $host2 =~ s/.* //; $host2 =~ s/\.$//; chomp $host2;
		chomp $a;
		chomp $b;


		# Existe t il deja un enregistrement ?
		$req= sprintf "SELECT count(*) FROM SMB1 WHERE src_ip = %s and dest_ip = %s",
		$dbh->quote_identifier($b), $dbh->quote($a);
		$tsh = $dbh->prepare($req);
		$tsh->execute();
		$found = $tsh->fetchrow_arrayref->[0];
		if ($found == 0) {
			print $req;
			print " $found\n";
		}

		# Si le couple ip source et ip destination n existe pas deja dans la bdd, on ajoute :
		if ($found == 0) {

			$src_os=`sudo nmap -O $b | grep Running | cut -d ":" -f2`; $src_os =~ s/^\s+//; chomp $src_os;
			$dest_os=`sudo nmap -O $a | grep Running | cut -d ":" -f2`; $dest_os =~ s/^\s+//; chomp $dest_os; 

			print "$b,$a,$host1,$host2,$src_os,$dest_os\n";

			eval {
				$dbh->do("INSERT INTO SMB1 (src_ip,dest_ip,src_host,dest_host,src_os,dst_os) VALUES ('$b','$a','$host1','$host2','$src_os','$dest_os')");
				1;
			}

			or do {
				$error = $@ || 'Unknown failure';
			}

		}

	}
}

$dbh->disconnect();
