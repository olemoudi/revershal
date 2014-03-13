#!/usr/bin/env python

'''
                             _           _ 
                            | |         | |
 _ __ _____   _____ _ __ ___| |__   __ _| |
| '__/ _ \ \ / / _ \ '__/ __| '_ \ / _` | |
| | |  __/\ V /  __/ |  \__ \ | | | (_| | |
|_|  \___| \_/ \___|_|  |___/_| |_|\__,_|_|
                                           
 Reverse hash cracker from known text Martin Obiols - @olemoudi -
 http://makensi.es


Reverse hash cracker to perform attacks from known plaintext tokens.

For example lets assume you have a hash and *you know* it is generated from
something like:

string = 'input1 + sep + input2 + sep + input3' hash = f(string)

From a security standpoint when the hash should not be guessable/predictable by
an attacker (for example in a reset password function), you should be using
HMAC or if you are so sloppy to use unkeyed hashes, you should at least make
one of the inputs a secret. However, multiple custom applications generate
hashes in this fashion just using predictable inputs such as email, full name,
userid or the timestamp of the instant they are generated. For example:

reset_password_hash = sha512( username + '.' + email + '.' + timestamp )

In this situation, getting knowledge about the particular input format that the
hashing function receives is the key to compromising the functionality (reset
        password in this case)

revershal does just that. Just feed it with your known predictable tokens and a
valid hash obtained from the application and it will compute all potential
formats, trying to come up with the one that was used.
'''

import sys
from itertools import permutations
import hashlib
import argparse
import time
from math import factorial
import multiprocessing
try:
    import pytz
    from pytz import timezone
except:
    print "You need pytz module"
    print "easy_install pytz"
    sys.exit(-1)
from multiprocessing import Queue, Lock, Value
from Queue import Empty, Full
import datetime
from datetime import timedelta


seps = ['|','+', '', ' ', '.', ':', ';', '-', '!', ',', '_']
sec_offset = 10 # seconds, to compensate for time offsets
queue = Queue() # to notify success
lock = Lock() 
statsqueue = Queue(maxsize=1) 
partial_counter = Value('i', 0, lock=True)
partial_time = time.time()
algos = {'md5' : 'd41d8cd98f00b204e9800998ecf8427e',
            'sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'sha224' : 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f',
            'sha256' : 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'sha384' : '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
            'sha512' : 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e'
            }

class colors:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD_SEQ = '\033[1m'

def pprint(msg, color=None, bold=False):
    global lock
    if bold:
        b = colors.BOLD_SEQ
    else:
        b = ''
    with lock:
        if color:
            print "%s%s%s%s" % (b, color, msg, colors.ENDC)
        else:
            print "%s%s" % (b, msg)

def msg(msg):
    pprint('[+] '+ msg)
def success(msg):
    pprint('[+] ' + msg, colors.GREEN, True)
def warning(msg):
    pprint('[+] ' + msg, colors.YELLOW)
def error(msg):
    pprint('[+] ' + msg, colors.RED, True)

banner = '''
\t                             _           _ 
\t                            | |         | |
\t _ __ _____   _____ _ __ ___| |__   __ _| |
\t| '__/ _ \ \ / / _ \ '__/ __| '_ \ / _` | |
\t| | |  __/\ V /  __/ |  \__ \ | | | (_| | |
\t|_|  \___| \_/ \___|_|  |___/_| |_|\__,_|_|
\t                                           
\t\t\t Reverse hash cracker from known tokens
\t\t\t Martin Obiols - @olemoudi - http://makensi.es
'''

def print_banner():
    global banner
    pprint(banner, colors.GREEN, bold=True)

def confirm(prompt=None, resp=False):
    """prompts for yes or no response from the user. Returns True for yes and
    False for no.

    'resp' should be set to the default value assumed by the caller when
    user simply types ENTER.
    """
    
    if prompt is None:
        prompt = 'Confirm'

    if resp:
        prompt = '%s [%s/%s]: ' % (prompt, 'Y', 'n')
    else:
        prompt = '%s [%s/%s]: ' % (prompt, 'y', 'N')
        
    while True:
        ans = raw_input(prompt)
        if not ans:
            return resp
        if ans not in ['y', 'Y', 'n', 'N']:
            print 'please enter y or n.'
            continue
        if ans == 'y' or ans == 'Y':
            return True
        if ans == 'n' or ans == 'N':
            return False

def guess(hash):
    '''
    Guess hash algorithm from string length
    '''
    global algos
    h = hash.strip()
    for algo in algos:
        if len(algos[algo]) == len(h):
            return algo
    error('Hash does not match any known algorithm')
    msg('Exiting...')
    sys.exit(-1)

def do_hash(inputs):
    '''
    1- Concats inputs list using different separators
    2- Hashes the resulting string
    3- Compares to target_hash
    '''
    global seps, algo, target_hash, queue, statsqueue, partial_counter
    use_seps = seps
    if len(inputs) == 1:
        # if input is a single element, there is no point on iterating seps
        use_seps = ['']
    for sep in use_seps:
        input_string = sep.join(inputs)
        hash = algo(input_string).hexdigest()
        if hash == target_hash:
            queue.put(input_string)
        else:
            try:
                statsqueue.put_nowait((input_string, hash))
            except Full:
                pass # other process already reported current item 
    with partial_counter.get_lock():
        partial_counter.value += len(use_seps)

def gen_dt_strings():
    '''
    Returns a set of all datetime strings after being formatted.
    Includes strings for different timezones and additional strings 
    to compensate for clock offsets as per sec_offset global var
    '''
    global date, dt_formats, sec_offset, total_dt_strings
    msg('Generating datetime strings for %i total formats...' % len(dt_formats))
    raw_dts = []
    for tz in pytz.all_timezones:
        zone = timezone(tz)
        for n in range(1, sec_offset+1):
            date1 = date + timedelta(seconds=n)
            raw_dts.append(date1.astimezone(zone))
            date2 = date - timedelta(seconds=n)
            raw_dts.append(date2.astimezone(zone))
    dt_strings = set() # we use unordered set to prevent duplicates
    for raw_dt in raw_dts:
        for format in dt_formats:
            dt_strings.add(raw_dt.strftime(format))
    msg('%i total datetime strings generated' % len(dt_strings))
    total_dt_strings = len(dt_strings)
    return dt_strings

def get_hash_inputs():
    '''
    Generator that returns ordered tuples of inputs 
    to be concatenated between seps before being hashed
    '''
    global inputs, lock, seps, dt_strings, inputs_finished
    # yield tokens as input one by one
    for item in inputs:
        yield (item,)
    # yield datetimes as input one by one
    for date_string in dt_strings:
        yield (date_string,)
    # yield permutations of tokens+datetimes of at least 2 length
    for date_string in dt_strings:
        base_inputs = list(inputs)
        base_inputs.append(date_string)
        for n in range(2, len(base_inputs) + 1):
            for input_set in permutations(base_inputs, n):
                yield input_set
    # flag when using imap
    inputs_finished = True

def calc_total(input_n):
    '''
    Calcs total hashes to compute from the number of inputs
    '''
    global seps, total_dt_strings
    total_inputs = input_n + 1 # tokens + datetime
    total = 0
    for n in range(2, total_inputs + 1):
        total += ( (factorial(total_inputs)/float(factorial(total_inputs-n))) * len(seps) )
    total = total * total_dt_strings
    total += (input_n + total_dt_strings)
    return total

def print_stats():
    '''
    Prints current try, speed and ETC
    '''
    global statsqueue, partial_counter, partial_time, total_hashes, partial_hashes
    with partial_counter.get_lock():
        c = partial_counter.value + 0.0001 # prevent division by zero
        partial_counter.value = 0
    partial_hashes += c
    now = time.time()
    diff = now - partial_time
    partial_time = now
    try:
        item = statsqueue.get_nowait()
        msg('Trying %s : %s (%i cps - ETC %s)' % (item[0], item[1], c/diff, str(timedelta(seconds=int((total_hashes-partial_hashes)*diff/c)))))
    except Empty:
        error('No items in the stats deque. Processes hung?')

def main():
    '''
    Main routine
    '''
    global algo, inputs, date, dt_formats, target_hash, partial_counter, partial_time, total_hashes, partial_hashes, dt_strings, inputs_finished
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--token-file', help='File containing known tokens (email, nick, id, password...), one per line', required=True)
    parser.add_argument('-f', '--date-formats', help='File containing strftime masks, one per line', required=False, default='timeformats.txt')
    parser.add_argument('-s', '--string-hash', help='Single hash to check', required=True)
    parser.add_argument('-d', '--date', help='server response HTTP Date header value', required=False, default='')
    parser.add_argument('-m', '--use-memory', help='Force pre-loading of permutations into memory to increase speed', required=False, action='store_true')
    args = parser.parse_args()

    print_banner()

    target_hash = args.string_hash.lower()
    alg_string = guess(args.string_hash)
    algo = getattr(hashlib, alg_string)
    msg('Hash algorithm: %s' % alg_string)
    inputs = set(filter(len, [l.strip() for l in open(args.token_file).readlines()]))
    inputs_finished = False
    msg('Known inputs are: %s' % (', '.join(inputs)))
    gmt = timezone('GMT')
    naive = datetime.datetime.strptime(args.date, '%a, %d %b %Y %H:%M:%S %Z')  # Wed, 23 Sep 2009 22:15:29 GMT
    date = gmt.localize(naive)
    dt_formats = filter(lambda x: x[0] != '#', filter(len, [l.strip() for l in open(args.date_formats).readlines()]))
    save_memory = not args.use_memory
    
    msg('%i total datetime formats loaded' % len(dt_formats))

    pool = multiprocessing.Pool(maxtasksperchild=1000000)
    try:
        dt_strings = gen_dt_strings()
        partial_time = time.time()
        partial_hashes = 0
        '''
        Depending on the amount of input we can pre-generate all input masks to memory (faster)
        or we need to use a generator and use imap
        '''
        if len(inputs) > 4:
            if save_memory:
                pool_result = pool.imap(do_hash, get_hash_inputs(), chunksize=100)
            else:
                warning('Danger, this may require A LOT of memory and potentially crash your system')
                result = confirm('Continue?')
                if result:
                    pool_result = pool.map_async(do_hash, get_hash_inputs())
                else:
                    sys.exit(1)
        else:
            pool_result = pool.map_async(do_hash, get_hash_inputs())
        total_hashes = calc_total(len(inputs)) 
        msg('%i total hashes to compute' % total_hashes)
        while True:
            try:
                result = queue.get(True, 3)
                print '\n'
                success("SUCCESS!!! \o/\n\n Pattern found:\n\t%s('%s') = %s" % (alg_string, result, target_hash ))
                print '\n'
                break
            except Empty:
                print_stats()
            finally:
                # slight sleep to prevent race condition between pool_result ready and queue empty
                time.sleep(.1) 
                # using imap
                if save_memory and len(inputs) > 4:
                    if inputs_finished:
                        error('No pattern found :C')
                        break
                else:
                    # using map_async
                    if pool_result.ready() and queue.empty():
                        error('No pattern found :C')
                        break

    except KeyboardInterrupt:
        pass
    finally:
        pool.terminate()
        pool.join()


if __name__ == '__main__':
    main()


        

