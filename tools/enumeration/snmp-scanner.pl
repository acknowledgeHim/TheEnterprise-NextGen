#!/usr/bin/perl 

use strict;
#command line option parsing
use Getopt::Long;
#thread stuff
use threads;
use threads::shared;
use Thread::Semaphore;
#snmp stuff
use Net::SNMP;

  
#declare some variables
my %opts;
my $thread_count;
my @community_strings;
my @threads;
my @hosts;
my @results;

#snmp declaration
my $sysDescr = '1.3.6.1.2.1.1.1.0';
my $sysUptime = '1.3.6.1.2.1.1.3.0';
my $sysName = '1.3.6.1.2.1.1.5.0';


#parse options, if illegal print usage info
GetOptions(\%opts, "h=s", "f=s", "t=i", "s=s", "o=s") || die &usage;

#make sure some sort of host was specified
if(!($opts{'h'}) && !($opts{'f'}))
{
  &usage;
}

#set thread count
$thread_count = $opts{'t'} || 20;

#handle external list of comminity strings
#if a file of strings is specified fill the array with those, otherwise use
#a small interal list
if($opts{'s'})
{
  open(IN, "<$opts{s}") || die "could not open $opts{s} for reading: $!\n";
  
  while(<IN>)
  {
    chomp;
    push(@community_strings, $_);
    print "$_\n";
  }
  close(IN);
  
}
else
{
#internal list of community strings
  @community_strings = (
    "PBECstring",
    "public",
    "private",
    "cisco",
    "internal",
    "manager",
    "system",
    "maintained",
    "monitor",
    "agent",
    "OrigEquipMfr",
    "tivoli",
    "openview",
    "community",
    "snmp",
    "snmpd",
    "Secret C0de",
    "security",
    "rmon",
    "rmon_admin",
    "hp_admin",
    "NoGaH\@!",
    "0392a0",
    "xyzzy",
    "agent_steal",
    "freekevin",
    "fubar",
    "apc",
    "ANYCOM",
    "cable-docis",
    "c",
    "cc",
    "Cisco router",
    "cascade",
    "comcomcom",
    "blue",
    "yellow",
    "TENmanUFactOryPOWER",
    "regional",
    "core",
    "secret",
    "write",
    "test",
    "guest",
    "ilmi",
    "ILMI",
    "system",
    "all",
    "admin",
    "all private",
    "password",
    "default",
    "riverhead",
    "proxy",
    "orion",
  );
}


#load a single host into our host list
my $hostcount = 0;
if($opts{'h'})
{
  $hosts[$hostcount++] = $opts{'h'};
}
#load a file of hosts into our host list
if($opts{'f'})
{
  open(IN, "<$opts{f}") || die "could not open host file $opts{H} for reading: $!\n";
  while(<IN>)
  {
    chomp;
#    push(@hosts, $_);
    $hosts[$hostcount++] = $_;
  }
}

#handle output file
if($opts{'o'})
{
  open(OUT, ">$opts{o}") || warn "COULD NOT OPEN $opts{o} FOR WRITING, OUTPUTTING TO STDOUT ONLY\n";
}

#############################
#begin main processing loop
#############################

my $limit = Thread::Semaphore->new($thread_count);
my $count = 0;

#create a thread for each host.  We will limit the number of concurrent threads
#in the function itself.  This makes life nice and easy for reporting in order
#and maintaining a sane number of threads running at a time
for(my $i = 0; $i < $hostcount;)
{
#  print "spawning thread $count\n";
  my $active_threads = 0;
  for(my $j = 0; $j < $thread_count && $i<$hostcount; $j++)
  {
    print "creating thread $j for host $i: $hosts[$i]\n";
    $threads[$j] = threads->new(\&testHost, $hosts[$i++]);
    $active_threads++;
  }
  print "adjusting i from $i to $i-$active_threads\n";
  $i = $i - $active_threads;
  for(my $j = 0; $j < $thread_count && $i<$hostcount; $j++)
  {
    print "joining thread $j for host $i: $hosts[$i]\n";
    $results[$i++] = $threads[$j]->join;
  }
}



#wait for the threads to end and get their data
#for(my $i = 0; $i < $hostcount; $i++)
#{
#  $results[$i] = $threads[$i]->join;
#}

#print out the results
for(my $i = 0; $i < $hostcount; $i++)
{
  print $results[$i];
  if($opts{'o'})
  {
    print OUT $results[$i];
  }
}

close(OUT);
###########################
#end main processing loop
###########################


#worker thread, polls host for SNMP info
sub testHost
{
  my $host = shift;
  $limit->down; #keep a reasonable number of threads

  my $validCS = "";
  my $csresp = "";
  my $csret;

  for(my $i=0; $i<scalar(@community_strings); $i++)
  {
    $csret = CSCheck($host, $community_strings[$i]);
    if($csret)
    {
      print "found community string $community_strings[$i] on $host\n";
      $validCS .= "$community_strings[$i] ";
      $csresp = $csret;
    }
  }
  

  $limit->up; #allow a new thread to start

  if($csresp eq "")
  {
    return;
  }
#  print "$host\t$validCS\t$csresp\n";
  return "$host\t$validCS\t$csresp\n";
}

#perform the actual community string check
sub CSCheck
{
  my $host = shift;
  my $string = shift;
  
  my $resp = "";
  my $ret = "";
 
  my ($session, $error) = Net::SNMP->session(
    Hostname	=> $host,
    Community	=> $string,
    Port	=> 161
    );
    
  if(!defined($session))
  {
    print "ERROR: $error\n";
    return;
  }

  $session->timeout(1);
  $session->retries(1);
  
  if(!defined($resp = $session->get_request($sysDescr)))
  {
    $session->close;
    return;
  }
 
  $ret = $resp->{$sysDescr};
  
  $resp = $session->get_request($sysName);
  $ret = $ret . "\t" . $resp->{$sysName};
  
#  print $ret;
  
  $session->close;
  return $ret;                                                                                                            
#  return $resp->{$sysDescr};
}

#print usage information
sub usage
{

print << "EOF";
USAGE:
single host: 
 $0 -h <host> [-t <thread count>] [-s <community string file>] [-o <output file>]
many hosts: 
 $0 -f <file> [-t <thread count>] [-s <community string file>] [-o <output file>]

Scans the specified hosts for SNMP community strings.  It will use a small 
internal list of strings by default, you can optionally specify your own list.

It will scan 20 hosts at a time by default to override this specify 
-t <thread count>

This tool is intended for internal use only.  It comes with no support and no
admission of liability.

contact bjohnson[at]larsonallen.com if you have any question. 

EOF


}
