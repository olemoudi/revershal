#!/usr/bin/python -u

'''
                             _           _ 
                            | |         | |
 _ __ _____   _____ _ __ ___| |__   __ _| |
| '__/ _ \ \ / / _ \ '__/ __| '_ \ / _` | |
| | |  __/\ V /  __/ |  \__ \ | | | (_| | |
|_|  \___| \_/ \___|_|  |___/_| |_|\__,_|_|
                                           
 Reverse hash cracker from known text
 Martin Obiols - @olemoudi - http://makensi.es


Reverse hash cracker to perform attacks from known plaintext tokens.

For example lets assume you have a hash and *you know* it is generated from
something like:

string = 'input1 + sep + input2 + input3'
hash = f(string)

From a security standpoint when the hash should not be guessable/predictable by an attacker (for example in a reset password function), at least one of those inputs should be kept secret. However, multiple custom make applications generate hashes in this fashion just using predictable inputs such as email, full name, userid or the timestamp of the instant they are generated. For example:

reset_password_hash = sha512( username + '.' + email + '.' + timestamp )

In this situation, getting knowledge about the particular input format that the hashing function receives is the key to compromising the functionality (reset password in this case)

revershal does just that. Just feed it with your known predictable tokens and a valid hash obtained from the application and it will compute all potential formats, trying to come up with the one that was used.
'''

import sys
from itertools import permutations
import hashlib
import argparse
import time
from math import factorial
import math
import multiprocessing
import ctypes

banner = '''
\t                             _           _ 
\t                            | |         | |
\t _ __ _____   _____ _ __ ___| |__   __ _| |
\t| '__/ _ \ \ / / _ \ '__/ __| '_ \ / _` | |
\t| | |  __/\ V /  __/ |  \__ \ | | | (_| | |
\t|_|  \___| \_/ \___|_|  |___/_| |_|\__,_|_|
\t                                           
\t\t\t Reverse hash cracker from known text
\t\t\t Martin Obiols - @olemoudi - http://makensi.es
'''

def process_tokens(known_tokens): 
    '''
    Just wrap couple of commands
    '''
    temp = []
    for i in known_tokens:
        temp.append(i)
    return list(set(temp))

global seps
seps = [',','|','+', '', ' ', '.', ':', ';', '-', '!', ',', '_']

def generate_masks(tokens, minutes=None):
    '''
    Iterator over generated masks.
    >>> for item in generate_masks(['a','b']):
            print item
    a
    b
    ab
    ba
    a.b
    b.a
    a,b
    b,a
    ... and so forth with all seps

    >>> for item in generate_masks(['a', 'b'], 1):
            print item
    a
    b
    ab
    ba
    [...] same results as with minutes=None and also
    a1338899067
    1338899067a
    b1338899067
    1338899067b
    a.1338899067
    a,1338899067
    [...]
    a.b.1338899067
    a,b,1338899067
    [...] repeat for all timestamps in the last minute (60 in total)


    '''
    global current_mask
    for length in range(len(tokens)+1)[1:]:
        for p in permutations(tokens, length):
            if len(p) == 1:
                current_mask.value = p[0]
                yield p[0]
            else:
                for s in seps:
                    mask = ''
                    for token in p:
                        if not len(mask) == 0:
                            mask += s
                        mask += '%s' % (token)
                    current_mask.value = mask
                    yield mask
            if minutes:
                for ts in get_timestamps(minutes):
                    for m in masks_with_timestamp(p, ts):
                        current_mask.value = m
                        yield m

def masks_with_timestamp(mask, ts):
    '''
    Insert timestamp on a given mask and return all combinations

    >>> for x in masks_with_timestamp(['a', 'b'], ts):
            print x

    axb
    xab
    abx
    a.x.b
    x.a.b
    a.b.x
    a,x,b
    ... and so forth with all seps
    '''
    mask = list(mask)
    result = []
    for n in range(len(mask)):
        temp = mask[:n]
        temp += [ts]
        temp += mask[n:]
        for s in seps:
            result.append(s.join(temp))
            result.append(s.join(mask+[ts]))
    return result


class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def pprint(color, msg):
    print "%s[*] %s%s" % (color, msg, colors.ENDC)

def header(msg, clean=False):
    pprint(colors.HEADER, msg)
def okblue(msg, clean=False):
    pprint(colors.OKBLUE, msg)
def okgreen(msg, clean=False):
    pprint(colors.OKGREEN, msg)
def warn(msg, clean=False):
    pprint(colors.WARNING, msg)
def fail(msg, clean=False):
    pprint(colors.FAIL, msg)


algos = {'md5' : 'd41d8cd98f00b204e9800998ecf8427e',
            'sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'sha224' : 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f',
            'sha256' : 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'sha384' : '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
            'sha512' : 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'
            }
def guess(hash):
    '''
    Guess hash algorithm from string length
    '''
    h = hash.strip()
    for algo in algos:
        if len(algos[algo]) == len(h):
            okblue("Hash looks like %s" % algo)
            return algo
    warn('Hash does not match any known algorithm')
    header('Exiting...')
    sys.exit(-1)

def check_algo(algo, hash):
    '''
    Checks algorithm is supported
    '''
    if len(algos[algo.strip()]) != len(hash.strip()):
        return False
    else:
        return True

def print_banner():
    header(banner)

def get_timestamps(minutes):
    '''
    Get all timestamps in the last [minutes] with integer resolution
    '''
    global current_time
    result = []
    for i in range((minutes*60)):
        result.append(str(current_time-i))
    return result

def stats_loop():
    '''
    Main process loop. Prints every 30 seconds stats about current status
    '''
    global found, total_checks, last_checks, clock, last_ts, algo, total, diff_mask
    exit = False
    time.sleep(2)
    while not found.value and not exit:
        newts = time.time()
        cps = math.ceil((last_checks.value+1)/(newts-last_ts.value))
        with clock:
            header("Testing %s(%s)... (%i c/s | ETA ~ %.2f hours)" % (algo, current_mask.value, cps, (((total-total_checks.value)/cps)/3600)))
        last_ts.value = int(newts)
        last_checks.value = 0

        for n in range(60):
            # dirty hack to check if mask iterator finished
            if not found.value and diff_mask != current_mask.value :
                diff_mask = current_mask.value
                time.sleep(0.5)
            elif diff_mask == current_mask.value:
                with clock:
                    fail('No hash matches target with current tokens')
                exit = True
                break
            else:
                # hash was found
                exit = True
                break

def mcrack(mask):
    '''
    Worker function that computes hashes
    '''
    global clock, total_checks, found, target_hash, last_checks, algo
    f = getattr(hashlib, algo)
    hash = f(mask).hexdigest()
    last_checks.value += 1
    total_checks.value += 1
    if hash == target_hash.value:
        found.value = True
        with clock:
            print
            okgreen('!'*30)
            okgreen("SUCCESS with mask: %s" % mask)
            okgreen('!'*30)
    
if __name__ == '__main__':

    # argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--token-file', help='File containing known tokens (email, nick, id, password...), one per line', required=True)
    parser.add_argument('-s', '--string-hash', help='Single hash to check against', required=True)
    parser.add_argument('-g', '--guess-algorithm', help='Try guessing the algorithm in use (checks only length)', action='store_true')
    parser.add_argument('--timestamps', help='Add integer timestamps for all the instants in the last X minutes in the past', default=None, type=int)
    parser.add_argument('-a', '--algorithm', help='Hash algorithm in use (default md5)', default='md5', choices=list(hashlib.algorithms))
    parser.add_argument('-p', '--processes', help='Parallel processes to use (default 2)', default=4, type=int)
    args = parser.parse_args()

    print_banner()

    global algo
    algo = args.algorithm

    if args.guess_algorithm:
        header("Guessing algorithm from hash...")
        warn('[WARNING] Guessing will only look at string length, not valid alphabet')
        algo = guess(args.string_hash)
    else:
        header("Algorithm is %s" % algo)

    tokens = process_tokens(filter(len, [x.strip() for x in open(args.token_file)]))

    header("Target hash: %s" % args.string_hash.strip())
    if not check_algo(algo, args.string_hash):
        fail("Hash does not look like %s" % algo)
        fail("Consider adding -g flag")
        header('Exiting...')
        sys.exit(-1)
    header('%i total known tokens' %len(tokens))

    masks = generate_masks(tokens, args.timestamps) 
            
    global total
    total = 0
    global current_time
    current_time = int(time.time())
    for n in range(len(tokens)+1)[1:]:
        if n == 1:
            total += (factorial(len(tokens))/factorial(len(tokens)-n))
        else:
            total += (factorial(len(tokens))/factorial(len(tokens)-n)) * len(seps) 
    if args.timestamps and args.timestamps > 0:
        for n in range(len(tokens)+1)[1:]:
            total += (factorial(len(tokens))/factorial(len(tokens)-n)) * (n+1) * args.timestamps * 60 * len(seps)
    header("Total of %i masks to compute..." % total)

    global clock
    clock = multiprocessing.Lock()
    global found
    found = multiprocessing.Value(ctypes.c_bool, False) 
    global target_hash
    target_hash = multiprocessing.Value(ctypes.c_char_p, args.string_hash.strip().lower()) 
    global current_mask, diff_mask
    current_mask = multiprocessing.Value(ctypes.c_char_p, '', lock=True) 
    diff_mask = current_mask.value
    global total_checks
    total_checks = multiprocessing.Value('i', 0)
    global last_checks
    last_checks = multiprocessing.Value('i', 0)
    global last_ts
    last_ts = multiprocessing.Value('i', int(time.time()))
    pool = multiprocessing.Pool(processes=args.processes)
    result_iterator = pool.imap(mcrack, masks, 10000)
    stats_loop()




