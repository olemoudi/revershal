REVERSHAL
=========


Reverse hash cracker from known text 
------------------------------------

Reverse hash cracker to perform attacks from known plaintext tokens.

For example lets assume you have a hash and *you know* it is generated from
something like:

    string = 'input1 + sep + input2 + sep + input3'
    hash = f(string)

From a security standpoint when the hash should not be guessable/predictable by an attacker (for example in a reset password function), at least one of those inputs should be a strong secret (key) known only by the application. However, multiple custom made applications generate hashes in this fashion just using predictable inputs such as email, full name, userid or the timestamp of the instant they are generated. For example:

    reset_password_hash = sha512( username + '-' + email + '-' + timestamp )

In this situation, getting knowledge about the particular input format that the hashing function receives is the key to compromising the functionality (reset password in this case)

revershal does just that. Just feed it with your known predictable tokens and a valid hash obtained from the application and it will compute all potential formats, trying to come up with the one that was used.

for example:

    $ cat test.txt
    token1
    token2
    token3
    $ ./revershal.py -t test.txt -s `echo -n "token1.token3.token2" | md5sum | cut -d" " -f1` -g 
    [*] Guessing algorithm from hash...
    [*] [WARNING] Guessing will only look at string length, not valid alphabet
    [*] Hash looks like md5
    [*] Target hash: 4615f95012f720eb5b23651debab6d78
    [*] 3 total known tokens
    [*] Total of 147 masks to compute...

    [*] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    [*] SUCCESS with mask: token1.token3.token2
    [*] !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


Martin Obiols - @olemoudi - http://makensi.es
