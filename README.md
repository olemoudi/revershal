REVERSHAL
=========


Reverse hash cracker from known text 
------------------------------------

Reverse hash cracker to perform attacks from known plaintext tokens.

For example lets assume you have a hash and *you know* it is generated from
something like:

    string = 'input1' + sep + 'input2' + sep + 'input3'
    hash = f(string)

From a security standpoint when the hash should not be guessable/predictable by an attacker (for example in a reset password function), you should be using HMAC functions or, at the very least, one of those inputs should be a strong secret (key) known only by the application. However, multiple custom made applications generate hashes in this fashion using predictable inputs such as email, full name, userid or the timestamp of the instant they are generated. For example:

    reset_password_hash = sha512( username + '-' + email + '-' + epoch_time() )

In this situation, getting knowledge about the particular input format that the hashing function receives is the key to compromising the functionality (reset password in this case)

revershal does just that. Just feed it with your known predictable tokens and a valid hash obtained from the application and it will compute all potential formats, trying to come up with the one that was used.

For example, let's say a password reset for account with known details such as email, username and user id receives a password reset link with an md5 token and the HTTP response Date header for the request was: Fri, 07 Mar 2014 11:00:03 GMT

    $ cat test.txt
    email@domain.com
    username
    890

    $ echo -n "email@domain.com:username:890:1394233198" | md5sum | cut -d" " -f1
    af3430d0a530171c8a1d2ad36d8cbcab

    $ ./revershal.py -t test.txt -s af3430d0a530171c8a1d2ad36d8cbcab -d "Fri, 07 Mar 2014 11:00:03 GMT"

    [+] Hash algorithm: md5
    [+] Known inputs are: username, 890, email@domain.com
    [+] 26 total datetime formats loaded
    [+] Generating datetime strings for 26 total formats...
    [+] 13720 total datetime strings generated
    [+] 9068923 total hashes to compute


    [+] SUCCESS!!! \o/

    Pattern found:
        md5('email@domain.com:username:890:1394233198') = af3430d0a530171c8a1d2ad36d8cbcab


Martin Obiols - @olemoudi - http://makensi.es
