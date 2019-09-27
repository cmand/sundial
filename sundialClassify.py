#!/usr/bin/env python
#
# Copyright (c) 2019, Erik Rye
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AN
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Program:      $Id: sundialClassify.py $
# Author:       Erik Rye <rye@cmand.org>
# Description:  https://www.cmand.org/sundial/
#
# Parses pcap_results.txt[.gz] file from timestampAnalyze. Produces the type
# classification breakdown used in the PAM 2019 paper.  
#
import sys
import gzip
import logging
import argparse
from tsutils import *
logging.basicConfig(format='%(filename)s:%(funcName)s:%(lineno)d: '\
        '%(levelname)s -- %(message)s', level=logging.INFO)

def addEntry(l, ip, origin, rx, tx, type_):
    '''
    Adds an entry to a list l. The value
    is a tuple that contains the origin, rx, tx, and type
    of request or reply. d is either a dictionary containing
    all of the requests, or all of the replies. 
    '''
    if not ip in d:
        d[ip] = [(origin, rx, tx, type_)]
    else:
        d[ip].append((origin,rx,tx, type_))

def runStats(requests, replies):
    '''
    runStats
    @params: 
    requests, dict of timestamp requests
        ip -> [(origin, rx, tx, type), ...]
    replies, dict of timestamp replies
        ip -> [(origin, rx, tx, type), ...]
    '''
    for ip in requests:
        reqs = requests[ip]
        if ip in replies:
           reps = replies[ip] 
        else:
            logging.debug("[+] IP %s: no replies", ip)
            continue
        fprint = classify(reqs, reps)
        if not fprint:
            continue

        if not fprint in fingerprints:
            fingerprints[fprint] = [ip]
        else:
            fingerprints[fprint].append(ip)

def printStats(results):
    '''
    printStats
    @params: 
    results, a dict of classifications -> counts
    '''
    for result in sorted(results.keys()):
        print result, results[result]

def writeStats(results, name):
    '''
    printStats
    @params: 
    results, a dict of classifications -> counts
    '''
    with open(name, "w") as f:
        for result in sorted(results.keys()):
            f.write(str(result)+','+str(results[result])+'\n')

def writeFingerprints(fingerprints, name):
    '''
    writeFingerprints
    @params: 
    results, a dict of fingerprints -> counts
    '''
    with open(name, "w") as g:
        for fprint in fingerprints:
            words = ','.join([fingerNames[idx] for idx, val in \
                    enumerate(fprint) if val])
            fname_words = '_'.join([fingerNames[idx] for idx, val in \
                    enumerate(fprint) if val]) + '.ips'
            if words:
                print words, ':', len(fingerprints[fprint])
                g.write(words+','+str(len(fingerprints[fprint]))+'\n')
                with open(fname_words, 'w') as f:
                    for ip in fingerprints[fprint]:
                        f.write(ip + '\n')
            else:
                print "Unknown:", len(fingerprints[fprint])
                g.write('unknown,'+str(len(fingerprints[fprint]))+'\n')
                with open('unknown.ips', 'w') as f:
                    for ip in fingerprints[fprint]:
                        f.write(ip + '\n')

def writeClassifications(fingerprints, name):
    '''
    '''
    with open(name, "w") as g:
        for fprint in fingerprints:
            words = ','.join([fingerNames[idx] for idx, val in \
                    enumerate(fprint) if val])
            for ip in fingerprints[fprint]:
              if words:
                  g.write(ip + ',' + words + '\n')
              else:
                  g.write(ip + ',unknown\n')

def classify(reqs, reps):
    '''
    classify
    @params:
    reqs, list of timestamp requests
    [(origin, rx, tx, type), ...]
    replies, list of timestamp requests
    [(origin, rx, tx, type), ...]
    Returns a tuple fingerprint
    of each category the IP fits into
    '''
    #########################
    #If we don't have all the requests,
    #then skip for now 
    #########################
    if not allRequests(reqs):
        return False

    #########################
    #If no replies,
    #skip
    #########################
    if not reps:
        return False

    ########################
    #Get a new fingerprint tuple
    ########################
    fprint = [0 for x in range(len(fingerNames))]

    results['total'] += 1

    if isNormal(reqs, reps):
        logging.debug("[+] Normal Reply")
        results['normal'] += 1
        fprint[NORMAL] = 1

    if isLazy(reqs, reps):
        logging.debug("[+] Lazy Reply")
        results['lazy'] += 1
        fprint[LAZY] = 1

    if isChecksumLazy(reqs, reps):
        logging.debug("[+] Checksum-Lazy Reply")
        results['checksumLazy'] += 1
        fprint[CHECKSUMLAZY] = 1

    stuck = isStuck(reqs, reps)
    if stuck:
        logging.debug("[+] Stuck Clock")
        if stuck == BOTH:
            results['stuck'] += 1
            fprint[STUCK] = 1
        elif stuck == RX_ONLY:
            results['stuckRx'] += 1
            fprint[STUCKRX] = 1
        elif stuck == TX_ONLY:
            results['stuckTx'] += 1
            fprint[STUCKTX] = 1
        else:
            logging.warn("Error! Shouldn't get here.")
            exit(1)

    ####################
    #Stuck at 0 clock
    ####################
    const = isConstant(reqs, reps, 0)
    if const:
        logging.debug("[+] Constant %s Clock", 0)
        if const == BOTH:
            results['stuck0'] += 1
            fprint[STUCK0] = 1
        elif const == RX_ONLY:
            results['stuck0Rx'] += 1
            fprint[STUCK0RX] = 1
        elif const == TX_ONLY:
            results['stuck0Tx'] += 1
            fprint[STUCK0TX] = 1
        else:
            logging.warn("Error! Shouldn't get here.")
            exit(1)

    ####################
    #Stuck at 1 clock
    ####################
    const = isConstant(reqs, reps, 1)
    if const:
        logging.debug("[+] Constant %s Clock", 1)
        if const == BOTH:
            results['stuck1'] += 1
            fprint[STUCK1] = 1
        elif const == RX_ONLY:
            results['stuck1Rx'] += 1
            fprint[STUCK1RX] = 1
        elif const == TX_ONLY:
            results['stuck1Tx'] += 1
            fprint[STUCK1TX] = 1
        else:
            logging.warn("Error! Shouldn't get here.")
            exit(1)

    ####################
    #Stuck at LE 1 clock
    ####################
    const = isConstant(reqs, reps, swap(1))
    if const:
        logging.debug("[+] Constant %s Clock", swap(1))
        if const == BOTH:
            results['stuckLE1'] += 1
            fprint[STUCKLE1] = 1
        elif const == RX_ONLY:
            results['stuckLE1Rx'] += 1
            fprint[STUCKLE1RX] = 1
        elif const == TX_ONLY:
            results['stuckLE1Tx'] += 1
            fprint[STUCKLE1TX] = 1
        else:
            logging.warn("Error! Shouldn't get here.")
            exit(1)

    echo = isEchoOrigin(reqs, reps)
    if echo:
        logging.debug("[+] Echo Origin Reply")
        if echo == BOTH:
            results['echo'] += 1
            fprint[ECHO] = 1
        elif echo == RX_ONLY:
            results['echoRx'] += 1
            fprint[ECHORX] = 1
        elif echo == TX_ONLY:
            fprint[ECHOTX] = 1
            results['echoTx'] += 1
        else:
            logging.warn("Error! Shouldn't get here.")
            exit(1)

    reflect = isReflection(reqs, reps)
    if reflect:
        logging.debug("[+] Reflect Reply")
        if reflect == BOTH:
            results['reflect'] += 1
            fprint[REFLECT] = 1
        elif reflect == RX_ONLY:
            results['reflectRx'] += 1
            fprint[REFLECTRX] = 1
        elif reflect == TX_ONLY:
            results['reflectTx'] += 1
            fprint[REFLECTTX] = 1
        else:
            logging.warn("Error! Shouldn't get here.")
            exit(1)

    tz, offset = isTimezone(reqs, reps)
    if tz:
        logging.debug("[+] Timezone Reply")
        if tz == BOTH:
            results['timezone'] += 1
            fprint[TIMEZONE] = 1
            if not offset in timezones:
                timezones[offset] = 1
            else:
                timezones[offset] += 1
        elif tz == RX_ONLY:
            results['timezoneRx'] += 1
            fprint[TIMEZONERX] = 1
            if not offset in timezones:
                timezones[offset] = 1
            else:
                timezones[offset] += 1
        elif tz == TX_ONLY:
            fprint[TIMEZONETX] = 1
            results['timezoneTx'] += 1
            if not offset in timezones:
                timezones[offset] = 1
            else:
                timezones[offset] += 1
        else:
            logging.warn("Error! Shouldn't get here.")
            exit(1)

    correct = isCorrect(reqs, reps)
    if correct:
        logging.debug("[+] Correct Reply")
        if correct == BOTH:
            fprint[CORRECT] = 1
            results['correct'] += 1
        elif correct == RX_ONLY:
            results['correctRx'] += 1
            fprint[CORRECTRX] = 1
        elif correct == TX_ONLY:
            fprint[CORRECTTX] = 1
            results['correctTx'] += 1
        else:
            logging.warn("Error! Shouldn't get here.")
            exit(1)

    correctLE = isCorrectLE(reqs, reps)
    if correctLE:
        logging.debug("[+] Correct LE Reply")
        if correctLE == BOTH:
            fprint[CORRECTLE] = 1
            results['correctLE'] += 1
        elif correctLE == RX_ONLY:
            fprint[CORRECTLERX] = 1
            results['correctLERx'] += 1
        elif correctLE == TX_ONLY:
            fprint[CORRECTLETX] = 1
            results['correctLETx'] += 1
        else:
            logging.warn("Error! Shouldn't get here.")
            exit(1)


    msb = isMSB(reqs, reps)
    if msb:
        logging.debug("[+] MSB Reply")
        if msb == BOTH:
            fprint[MSB] = 1
            results['msb'] += 1
        elif msb == RX_ONLY:
            fprint[MSBRX] = 1
            results['msbRx'] += 1
        elif msb == TX_ONLY:
            fprint[MSBTX] = 1
            results['msbTx'] += 1
        else:
            logging.warn("Error! Shouldn't get here.")
            exit(1)


    correctMSB = isCorrectMSB(reqs, reps)
    if correctMSB:
        logging.debug("[+] Correct MSB Reply")
        if correctMSB == BOTH:
            fprint[CORRECTMSB] = 1
            results['correctMSB'] += 1
        elif correctMSB == RX_ONLY:
            fprint[CORRECTMSBRX] = 1
            results['correctMSBRx'] += 1
        elif correctMSB == TX_ONLY:
            fprint[CORRECTMSBTX] = 1
            results['correctMSBTx'] += 1
        else:
            logging.warn("Error! Shouldn't get here.")
            exit(1)

    buggy = isBuggy(reqs, reps)
    if buggy:
        logging.debug("[+] Buggy Reply")
        fprint[BUGGY] = 1
        results['buggy'] += 1

    ms = isCountingMs(reqs, reps)
    if ms:
        logging.debug("[+] Millisecond Counting Reply")
        if ms == BOTH:
            fprint[MS] = 1
            results['millisecond'] += 1
        elif ms == RX_ONLY:
            fprint[MSRX] = 1
            results['millisecondRx'] += 1
        elif ms == TX_ONLY:
            fprint[MSTX] = 1
            results['millisecondTx'] += 1
        else:
            logging.warn("Error! Shouldn't get here.")
            exit(1)

    s = isCountingS(reqs, reps)
    if s:
        logging.debug("[+] Second Counting Reply")
        if s == BOTH:
            fprint[S] = 1
            results['second'] += 1
        elif s == RX_ONLY:
            fprint[SRX] = 1
            results['secondRx'] += 1
        elif s == TX_ONLY:
            fprint[STX] = 1
            results['secondTx'] += 1
        else:
            logging.warn("Error! Shouldn't get here.")
            exit(1)

    s = isEpoch(reqs, reps)
    if s:
        logging.debug("[+] Epoch Reply")
        if s == BOTH:
            fprint[EPOCH] = 1
            results['epoch'] += 1
        elif s == RX_ONLY:
            fprint[EPOCHRX] = 1
            results['epochRx'] += 1
        elif s == TX_ONLY:
            fprint[EPOCHTX] = 1
            results['epochTx'] += 1
        else:
            logging.warn("Error! Shouldn't get here.")
            exit(1)
   

    #########################
    #Return the fingerprint tuple
    #########################
    return tuple(fprint)

def isEpoch(reqs, reps):
    '''
    Determines whether some destination is replying with
    epoch time
    @params:
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    @return value
    BOTH if both rx and tx timestamps are epoch
    RX_ONLY
    TX_ONLY
    We've got the epoch time in the timestamp tuple, so let's just check that
    we're within +/- a second
    '''
    ###################
    # Get standard request 
    ###################
    standardReq = getRequestByType(REQ_STANDARD, reqs)
    logging.debug("Standard request: %s", standardReq)
    standardReply = getReplyByTimestamp(standardReq[O_TUP], reps)
    logging.debug("Standard reply: %s", standardReply)

    ###################
    #If there's a no standard 
    #request reply, then quit
    ###################
    if not standardReply: 
        return False

    standardRepRx = standardReply[RX_TUP]
    standardRepTx = standardReply[TX_TUP]
    standardRepEpoch = int(standardReply[TIME_TUP])

    if (abs(standardRepRx - standardRepEpoch) <= 1 and 
            abs(standardRepTx - standardRepEpoch) <= 1):
        return BOTH
    elif (abs(standardRepRx - standardRepEpoch) <= 1):
        return RX_ONLY
    elif (abs(standardRepTx - standardRepEpoch) <= 1):
        return TX_ONLY
    else:
        return False


def isCountingS(reqs, reps):
    '''
    Determines whether some destination is counting
    in seconds or not.
    @params:
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    @return value
    BOTH if both rx and tx timestamps are correct
    RX_ONLY
    TX_ONLY
    Determine how long elapsed between two successive replies from a host using
    standard and duplicate timestamp requests. Then, compare to what is inferred
    from looking at the receive and transmit timestamps in the replies
    '''
    ###################
    # Get standard request 
    ###################
    standardReq = getRequestByType(REQ_STANDARD, reqs)
    logging.debug("Standard request: %s", standardReq)
    standardReply = getReplyByTimestamp(standardReq[O_TUP], reps)
    logging.debug("Standard reply: %s", standardReply)

    ###################
    #If there's a no standard 
    #request reply, then quit
    ###################
    if not standardReply: 
        return False

    ###################
    # Get duplicate timestamp 
    # request reply
    ###################
    duplicateReq = getRequestByType(REQ_DUPLICATE_TS, reqs)
    logging.debug("Duplicate request: %s", duplicateReq)
    duplicateReply = getReplyByTimestamp(duplicateReq[O_TUP], reps)
    logging.debug("Duplicate reply: %s", duplicateReply)

    ###################
    #If there's a no duplicate 
    #request reply, then quit
    ###################
    if not duplicateReply: 
        return False

    ###Get actual times first###
    standardRepRecv = standardReply[TIME_TUP]
    duplicateRepRecv = duplicateReply[TIME_TUP]
    logging.debug("Standard reply recv: %f, duplicate reply recv: %f",
            standardRepRecv, duplicateRepRecv)

    #calculate real *seconds* between receives
    realDiff = int(duplicateRepRecv - standardRepRecv)
    logging.debug("Calculated real time difference between receives: %d",
            realDiff)


    ###Get times from replies###
    standardRepRx = standardReply[RX_TUP]
    standardRepTx = standardReply[TX_TUP]
    duplicateRepRx = duplicateReply[RX_TUP]
    duplicateRepTx = duplicateReply[TX_TUP]

    #I'm going to assume if something counts in seconds, it doesn't do so modulo
    #a day's seconds...because that'd be weird, right?
    inferredRxTime = (standardRepRx + realDiff) 
    inferredTxTime = (standardRepTx + realDiff) 

    if abs(inferredRxTime - duplicateRepRx) < 2 *  ERROR_MARGIN and\
            abs(inferredTxTime - duplicateRepTx) < 2 * ERROR_MARGIN:
        return BOTH
    elif abs(inferredRxTime - duplicateRepRx) < 2 * ERROR_MARGIN:
        return RX_ONLY
    elif abs(inferredTxTime - duplicateRepTx) <2 * ERROR_MARGIN:
        return TX_ONLY
    else:
        return False

def isCountingMs(reqs, reps):
    '''
    Determines whether some destination is counting
    in milliseconds or not.
    @params:
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    @return value
    BOTH if both rx and tx timestamps are correct
    RX_ONLY
    TX_ONLY
    Determine how long elapsed between two successive replies from a host using
    standard and duplicate timestamp requests. Then, compare to what is inferred
    from looking at the receive and transmit timestamps in the replies
    '''
    ###################
    # Get standard request 
    ###################
    standardReq = getRequestByType(REQ_STANDARD, reqs)
    logging.debug("Standard request: %s", standardReq)
    standardReply = getReplyByTimestamp(standardReq[O_TUP], reps)
    logging.debug("Standard reply: %s", standardReply)

    ###################
    #If there's a no standard 
    #request reply, then quit
    ###################
    if not standardReply: 
        return False

    ###################
    # Get duplicate timestamp 
    # request reply
    ###################
    duplicateReq = getRequestByType(REQ_DUPLICATE_TS, reqs)
    logging.debug("Duplicate request: %s", duplicateReq)
    duplicateReply = getReplyByTimestamp(duplicateReq[O_TUP], reps)
    logging.debug("Duplicate reply: %s", duplicateReply)

    ###################
    #If there's a no duplicate 
    #request reply, then quit
    ###################
    if not duplicateReply: 
        return False

    ###Get actual times first###
    standardRepRecv = standardReply[TIME_TUP]
    duplicateRepRecv = duplicateReply[TIME_TUP]
    logging.debug("Standard reply recv: %f, duplicate reply recv: %f",
            standardRepRecv, duplicateRepRecv)

    #calculate real *milliseconds* between receives
    realDiff = int((duplicateRepRecv - standardRepRecv) * 1000)
    logging.debug("Calculated real time difference between receives: %d",
            realDiff)


    ###Get times from replies###
    standardRepRx = standardReply[RX_TUP]
    standardRepTx = standardReply[TX_TUP]
    duplicateRepRx = duplicateReply[RX_TUP]
    duplicateRepTx = duplicateReply[TX_TUP]

    inferredRxTime = (standardRepRx + realDiff) % DAY_MILLISECONDS
    inferredTxTime = (standardRepTx + realDiff) % DAY_MILLISECONDS

    if abs(inferredRxTime - duplicateRepRx) < 2 *  ERROR_MARGIN and\
            abs(inferredTxTime - duplicateRepTx) < 2 * ERROR_MARGIN:
        return BOTH
    elif abs(inferredRxTime - duplicateRepRx) < 2 * ERROR_MARGIN:
        return RX_ONLY
    elif abs(inferredTxTime - duplicateRepTx) <2 * ERROR_MARGIN:
        return TX_ONLY
    else:
        return False


def isCorrect(reqs, reps):
    '''
    Determines whether a standard reply
    is correct or not
    @params:
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    @return value
    Correctness defined in ERROR_MARGIN
    BOTH if both rx and tx timestamps are correct
    RX_ONLY
    TX_ONLY
    Correct -- can be determined w/standard request/reply
    '''
    ###################
    # Get standard request 
    ###################
    standardReq = getRequestByType(REQ_STANDARD, reqs)
    logging.debug("Standard request: %s", standardReq)
    standardReply = getReplyByTimestamp(standardReq[O_TUP], reps)
    logging.debug("Standard reply: %s", standardReply)

    ###################
    #If there's a no standard 
    #request reply, then quit
    ###################
    if not standardReply: 
        return False

    rx = standardReply[RX_TUP]
    tx = standardReply[TX_TUP]
    origin = standardReply[O_TUP]

    if abs(rx - origin) < ERROR_MARGIN and \
            abs(tx - origin) < ERROR_MARGIN:
        return BOTH
    elif  abs(rx - origin) < ERROR_MARGIN:
        return RX_ONLY
    elif  abs(tx - origin) < ERROR_MARGIN:
        return TX_ONLY
    return False

def isCorrectLE(reqs, reps):
    '''
    Determines whether a standard reply
    is correct or not when reply is LE
    @params:
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    @return value
    Correctness defined in ERROR_MARGIN
    BOTH if both rx and tx timestamps are correct
    RX_ONLY
    TX_ONLY
    Correct -- can be determined w/standard request/reply
    '''
    ###################
    # Get standard request 
    ###################
    standardReq = getRequestByType(REQ_STANDARD, reqs)
    logging.debug("Standard request: %s", standardReq)
    standardReply = getReplyByTimestamp(standardReq[O_TUP], reps)
    logging.debug("Standard reply: %s", standardReply)

    ###################
    #If there's a standard request reply,
    #then check that 0 != rx != tx != 0
    ###################
    if not standardReply: 
        return False

    rx = swap(standardReply[RX_TUP])
    tx = swap(standardReply[TX_TUP])
    origin = standardReply[O_TUP]

    if abs(rx - origin) < ERROR_MARGIN and \
            abs(tx - origin) < ERROR_MARGIN:
        return BOTH
    elif  abs(rx - origin) < ERROR_MARGIN:
        return RX_ONLY
    elif  abs(tx - origin) < ERROR_MARGIN:
        return TX_ONLY
    return False

def isMSB(reqs, reps):
    '''
    Determines whether a standard reply
    returns a MSB-set timestamp
    @params:
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    @return value
    BOTH if both rx and tx timestamps have msb set
    RX_ONLY
    TX_ONLY
    Can be determined w/standard request/reply
    '''
    ###################
    # Get standard request 
    ###################
    standardReq = getRequestByType(REQ_STANDARD, reqs)
    logging.debug("Standard request: %s", standardReq)
    standardReply = getReplyByTimestamp(standardReq[O_TUP], reps)
    logging.debug("Standard reply: %s", standardReply)

    ###################
    #If there's a standard request reply,
    #then check that 0 != rx != tx != 0
    ###################
    if not standardReply: 
        return False

    rx = standardReply[RX_TUP]
    tx = standardReply[TX_TUP]
    if rx < MIN_NONUTC and tx < MIN_NONUTC:
        return False
    elif rx >= MIN_NONUTC and tx >= MIN_NONUTC:
        return BOTH
    elif rx >= MIN_NONUTC:
        return RX_ONLY
    elif tx >= MIN_NONUTC:
        return TX_ONLY
    else:
        logging.warn("Shouldn't reach this point. Exiting")
        sys.exit(1)

def isBuggyReply(reply):
    '''
    isBuggyReply
    @params reply, a timestamp reply tuple (o, rx, tx, type)
    @return True if the reply is buggy, e.g. rx == tx != 0
    False else
    '''
    rx = reply[RX_TUP]
    tx = reply[TX_TUP]

    rxLower0 = ((rx & 0x0000ffff) == 0) and rx != 0 and rx != swap(1)
    txLower0 = ((tx & 0x0000ffff) == 0) and tx != 0 and tx != swap(1)

    if rxLower0 and txLower0:
        return True
    return False

def isBuggy(reqs, reps):
    '''
    Determines whether a remote host has
    the htons() bug
    @params:
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    @return value
    BOTH if both rx and tx timestamps have msb set
    RX_ONLY
    TX_ONLY
    New from PAM -- only classify as buggy if *all* available replies are buggy.
    Is buggy if in both reply timestamps the lower two bytes are 00 00
    '''
    #########################
    #Iterate through requests
    #########################
    for reqType in [REQ_STANDARD, REQ_BAD_CLOCK, REQ_BAD_CHECKSUM,
            REQ_DUPLICATE_TS]:
        req = getRequestByType(reqType, reqs)
        logging.debug("Request: %s", req)
        rep = getReplyByTimestamp(req[O_TUP], reps)
        logging.debug("Reply: %s", req)
        ####################
        #if there isn't a reply 
        #for this request, that's ok,
        #just goto next type
        ########################
        if not rep:
            continue
        ######################
        #if this is *not* buggy, we 
        #break out and return false now
        #######################
        if not isBuggyReply(rep):
            return False

    ###################
    #If we got here, 
    #it's buggy
    ##################
    return True

def isCorrectMSB(reqs, reps):
    '''
    Determines whether a standard reply
    is correct or not when MSB turned off, if on
    @params:
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    @return value
    Correctness defined in ERROR_MARGIN
    BOTH if both rx and tx timestamps are correct
    RX_ONLY
    TX_ONLY
    Correct MSB -- can be determined w/standard request/reply
    '''
    ###################
    # Get standard request 
    ###################
    standardReq = getRequestByType(REQ_STANDARD, reqs)
    logging.debug("Standard request: %s", standardReq)
    standardReply = getReplyByTimestamp(standardReq[O_TUP], reps)
    logging.debug("Standard reply: %s", standardReply)

    ###################
    #If there's a standard request reply,
    #then check that 0 != rx != tx != 0
    ###################
    if not standardReply: 
        return False

    rx = standardReply[RX_TUP]
    tx = standardReply[TX_TUP]
    if rx < MIN_NONUTC and tx < MIN_NONUTC:
        return False

    origin = standardReply[O_TUP]
    rx -= MIN_NONUTC
    tx -= MIN_NONUTC

    if abs(rx - origin) < ERROR_MARGIN and \
            abs(tx - origin) < ERROR_MARGIN:
        return BOTH
    elif  abs(rx - origin) < ERROR_MARGIN:
        return RX_ONLY
    elif  abs(tx - origin) < ERROR_MARGIN:
        return TX_ONLY
    return False


def allRequests(reqs):
    '''
    allRequests
    @params 
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    @return value
    True if all 4 timestamp request types are present
    False otherwise
    '''
    logging.debug("[+] In allRequests()")
    types = [x[-1] for x in reqs]
    logging.debug("[+] %s", types)
    if sorted(types) == range(4):
        return True
    logging.warn("Skipping target, expected 4 response types, got %s" % str(sorted(types)))
    return False

def isNormalReply(reply):
    '''
    isNormalReply
    @params
    a timestamp reply tuple (o,rx,tx,type_)
    @return True if the reply is "normal" 
    according to the PAM definition 0 != rx != tx != 0
    False else
    '''
    rx = reply[RX_TUP]
    tx = reply[TX_TUP]
    if rx != tx and tx != 0 and rx != 0:
        return True
    return False

def isNormal(reqs, reps):
    '''
    isNormal
    Determines whether a responding host is "normal"
    or not
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    reps, a list of timestamp replies
    [(origin, rx, tx, type), ...]
    @return value
    True if indicative of a normal responding IP
    False otherwise
    Normal -- 0 != rx != tx != 0. True if **ANY**
    of the replies are normal, not just if the standard
    request reply is normal (change from PAM)
    '''

    #########################
    #Iterate through requests
    #########################
    for reqType in [REQ_STANDARD, REQ_BAD_CLOCK, REQ_BAD_CHECKSUM,
            REQ_DUPLICATE_TS]:
        req = getRequestByType(reqType, reqs)
        logging.debug("Request: %s", req)
        rep = getReplyByTimestamp(req[O_TUP], reps)
        logging.debug("Reply: %s", req)
        ####################
        #if there isn't a reply 
        #for this request, that's ok,
        #just goto next type
        ########################
        if not rep:
            continue
        ######################
        #if this reply is normal,
        #we know this is a normal
        #box, so return true now
        #######################
        if isNormalReply(rep):
            return True

    ################################################
    #If we get here, then all of the reply timestamps 
    #were lazy. There had to be at least one, or we
    #wouldn't be classifying, so that's enough for me.
    ################################################

    return False

def isLazyReply(reply):
    '''
    isLazyReply
    @params reply, a timestamp reply tuple (o, rx, tx, type)
    @return True if the reply is lazy, e.g. rx == tx != 0
    False else
    '''
    rx = reply[RX_TUP]
    tx = reply[TX_TUP]

    if rx == tx and tx != 0 and rx not in CONSTANTS:
        return True
    return False

def isLazy(reqs, reps):
    '''
    isLazy()
    Determines whether a responding host is "lazy" or not
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    reps, a list of timestamp replies
    [(origin, rx, tx, type), ...]
    @return value
    True if **all** timestamp replies are lazy. This is
    a change from PAM. A responder can be classified as lazy
    if it's really normal, but all of its rx/tx timestamps are
    marked sub-ms. So, we are only going with true if all of the
    replies indicate lazy. If *any* are normal, we immediately return 
    False. As a reminder, Lazy --> 0 != rx == tx
    Also new from PAM -- lazy excludes other non-zero constants, e.g.
    1/LE 1
    '''
    #########################
    #Iterate through requests
    #########################
    for reqType in [REQ_STANDARD, REQ_BAD_CLOCK, REQ_BAD_CHECKSUM,
            REQ_DUPLICATE_TS]:
        req = getRequestByType(reqType, reqs)
        logging.debug("Request: %s", req)
        rep = getReplyByTimestamp(req[O_TUP], reps)
        logging.debug("Reply: %s", req)
        ####################
        #if there isn't a reply 
        #for this request, that's ok,
        #just goto next type
        ########################
        if not rep:
            continue
        ######################
        #if this is *not* lazy, we 
        #return false now
        #######################
        if not isLazyReply(rep):
            return False

    #####################
    #If we got here, everything
    #was lazy, so that's our best guess
    #It compiles, ship it.
    #####################
    return True

def isStuck(reqs, reps):
    '''
    isStuck()
    Determines whether a responding host has
    a "stuck clock" or not
    @params:
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    reps, a list of timestamp replies
    [(origin, rx, tx, type), ...]
    @return value
    True if indicative of a "stuck" responding IP
    False otherwise
    Stuck -- reply1 rx == reply2 rx and tx == rx
    Reply1 is reply to normal request, reply2 is duplicate timestamp
    '''
    ###################
    # Get standard request 
    ###################
    standardReq = getRequestByType(REQ_STANDARD, reqs)
    logging.debug("Standard request: %s", standardReq)
    standardReply = getReplyByTimestamp(standardReq[O_TUP], reps)
    logging.debug("Standard reply: %s", standardReply)

    ###################
    # Get duplicate ts request 
    ###################
    dupReq = getRequestByType(REQ_DUPLICATE_TS, reqs)
    logging.debug("Duplicate request: %s", dupReq)
    dupReply = getReplyByTimestamp(dupReq[O_TUP], reps)
    logging.debug("Duplicate reply: %s", dupReply)

    ###################
    #If there's a not standard request reply,
    #or not a dupReply, can't say.
    ###################
    if not standardReply or not dupReply: 
        return False

    rx = standardReply[RX_TUP]
    tx = standardReply[TX_TUP]

    dupRx = dupReply[RX_TUP] 
    dupTx = dupReply[TX_TUP] 

    if rx == dupRx and tx == dupTx and rx == tx:
        return BOTH
    elif rx == dupRx:
        return RX_ONLY
    elif tx == dupTx:
        return TX_ONLY
    return False

def isConstant(reqs, reps, const):
    '''
    isConstant()
    Determines whether a responding host has
    a "stuck clock" or not at the "const" value
    @params:
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    reps, a list of timestamp replies
    [(origin, rx, tx, type), ...]
    const -- some constant value to check
    if the clock is stuck at
    @return value
    True if clock is stuck at const
    False otherwise
    isConstant --  isStuck and timestamps == const
    '''

    ###################
    #isConst is a struct 
    #subset of isStuck,
    #so check that first
    ###################

    if not isStuck(reqs, reps):
        return False

    ###################
    # Get standard request 
    ###################
    logging.debug("[+] In isStuck()")
    standardReq = getRequestByType(REQ_STANDARD, reqs)
    logging.debug("Standard request: %s", standardReq)
    standardReply = getReplyByTimestamp(standardReq[O_TUP], reps)
    logging.debug("Standard reply: %s", standardReply)

    rx = standardReply[RX_TUP]
    tx = standardReply[TX_TUP]

    if rx == const and tx == const:
        return BOTH
    elif rx == const:
        return RX_ONLY
    elif tx == const:
        return TX_ONLY
    return False

def isChecksumLazy(reqs, reps):
    '''
    isChecksumLazy()
    Determines whether a responding host is "checksum lazy" or not
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    reps, a list of timestamp replies
    [(origin, rx, tx, type), ...]
    @return value
    True if indicative of a "checksum lazy" responding IP
    False otherwise
    Checksum Lazy: responds to packet w/incorrect checksum
    '''
    ###################
    # Get incorrect checksum request 
    ###################
    logging.debug("[+] In isChecksumLazy()")
    badChecksumReq = getRequestByType(REQ_BAD_CHECKSUM, reqs)
    logging.debug("Bad checksum request: %s", badChecksumReq)
    badChecksumReply = getReplyByTimestamp(badChecksumReq[O_TUP], reps)
    logging.debug("Bad checksum reply: %s", badChecksumReply)

    ###################
    #If there's a bad checksum request reply,
    #return true
    ###################
    if badChecksumReply: 
        return True

    return False

def isTZTimestamp(origin, ts):
    '''
    Determines whether a timestamp (ts) is a 
    timezone offset off of the originate timestamp
    '''
    for x in list(range(-12,0)) + list(range(1,13)) + \
            [-3.5,-2.5,3.5,4.5,5.5,6.5,9.5,10.5]:
        offset = (origin + (x * HOUR_MILLISECONDS)) % DAY_MILLISECONDS
        if abs(ts - offset) < ERROR_MARGIN:
            return x
    return False

def isEchoOrigin(reqs, reps):
    '''
    isEchoOrigin()
    Determines whether a responding host is
    just echoing the origin timestamp into the
    receive and transmit fields
    @params:
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    reps, a list of timestamp replies
    [(origin, rx, tx, type), ...]
    @return value
    True if EchoOrigin
    False otherwise
    isEchoOrigin -- Need standard request, and
    "bad clock request". Is an echo origin host
    if standard reply rx == tx == request's origin
    AND bad clock reply rx == tx == bad clock request's origin
    '''

    logging.debug("[+] In isEchoOrigin()")
    ###################
    # Get standard request 
    ###################
    standardReq = getRequestByType(REQ_STANDARD, reqs)
    logging.debug("Standard request: %s", standardReq)
    standardReply = getReplyByTimestamp(standardReq[O_TUP], reps)
    logging.debug("Standard reply: %s", standardReply)

    ###################
    # Get bad clock request 
    ###################
    badClockReq = getRequestByType(REQ_BAD_CLOCK, reqs)
    logging.debug("Bad clock request: %s", badClockReq)
    badClockReply = getReplyByTimestamp(badClockReq[O_TUP], reps)
    logging.debug("Bad clock reply: %s", badClockReply)


    ################
    #If we don't have one of the two
    #replies, we can't tell. Return false
    ################
    if not standardReply or not badClockReply:
        return False

    rx = standardReply[RX_TUP]
    tx = standardReply[TX_TUP]
    origin = standardReply[O_TUP]
    badClockRx = badClockReply[RX_TUP]
    badClockTx = badClockReply[TX_TUP]
    badClockOrigin = badClockReply[O_TUP]


    if (origin == rx and rx == tx) and \
        (badClockOrigin == badClockRx and badClockRx == badClockTx):
        return BOTH
    elif (origin == rx and badClockOrigin == badClockRx):
        return RX_ONLY
    elif (origin == tx and badClockOrigin == badClockTx):
        return TX_ONLY
    return False

def isReflection(reqs, reps):
    '''
    isReflection()
    Determines whether a responding host is reflecting the rx and tx timestamps
    of the requests it receives in its receive and transmit fields
    @params:
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    reps, a list of timestamp replies
    [(origin, rx, tx, type), ...]
    @return value
    True if reflection
    False otherwise
    reflection -- Need standard request, and
    a "duplicate ts request". Is an reflection host
    if standard reply rx == tx == standard request's rx & tx AND duplicate ts
    request rx == tx == duplicate ts request's rx & tx
    '''

    logging.debug("[+] In isReflection()")
    ###################
    # Get standard request 
    ###################
    standardReq = getRequestByType(REQ_STANDARD, reqs)
    logging.debug("Standard request: %s", standardReq)
    standardReply = getReplyByTimestamp(standardReq[O_TUP], reps)
    logging.debug("Standard reply: %s", standardReply)

    ###################
    # Get duplicate ts request 
    ###################
    dupReq = getRequestByType(REQ_DUPLICATE_TS, reqs)
    logging.debug("Duplicate request: %s", dupReq)
    dupReply = getReplyByTimestamp(dupReq[O_TUP], reps)
    logging.debug("Duplicate reply: %s", dupReply)


    ################
    #If we don't have one of the two
    #replies, we can't tell. Return false
    ################
    if not standardReply or not dupReply:
        return False

    reqRx = standardReq[RX_TUP]
    reqTx = standardReq[TX_TUP]
    rx = standardReply[RX_TUP]
    tx = standardReply[TX_TUP]

    dupReqRx = dupReq[RX_TUP]
    dupReqTx = dupReq[TX_TUP]
    dupRx = dupReply[RX_TUP]
    dupTx = dupReply[TX_TUP]
        
    if (reqRx == rx and reqTx == tx)  and \
            (dupReqRx == dupRx and dupReqTx == dupTx):
        return BOTH
    elif (reqRx == rx) and (dupReqRx == dupRx):
        return RX_ONLY
    elif (reqRx == rx) and (dupReqTx == dupTx):
        return TX_ONLY
    return False

def isTimezone(reqs, reps):
    '''
    isTimezone()
    Determines whether a responding host is using local time
    in the timestamps it returns
    @params:
    reqs, a list of timestamp requests
    [(origin, rx, tx, type), ...]
    reps, a list of timestamp replies
    [(origin, rx, tx, type), ...]
    @return value
    BOTH if both are timezone replies, RX_ONLY if
    only the receive timestamp is, and TX_ONLY if only the
    transmit timestamp is
    False otherwise
    '''

    logging.debug("[+] In isTimezone()")
    ###################
    # Get standard request 
    ###################
    standardReq = getRequestByType(REQ_STANDARD, reqs)
    logging.debug("Standard request: %s", standardReq)
    standardReply = getReplyByTimestamp(standardReq[O_TUP], reps)
    logging.debug("Standard reply: %s", standardReply)

    ################
    #If we don't have a standard reply,
    #return
    ################
    if not standardReply:
        return False, False

    origin = standardReply[O_TUP]
    rx = standardReply[RX_TUP]
    tx = standardReply[TX_TUP]

    rxTZ = isTZTimestamp(origin, rx)
    txTZ = isTZTimestamp(origin, tx)

    if rxTZ and txTZ and rxTZ == txTZ: 
        return BOTH, rxTZ
    elif rxTZ and txTZ and rxTZ != txTZ: 
        logging.warn("[+] Timezones on timestamps not equal")
        exit(1)
    elif rxTZ:
        return RX_ONLY, rxTZ
    elif txTZ:
        return TX_ONLY, txTZ
    return False, False

def getReplyByTimestamp(ts, reps):
    '''
    getReplyByTimestamp
    @params, ts -- an originate timestamp
    reps -- a list of timestamp replies
    Given a list of timestamp replies,
    returns the tuple whose originate timestamp
    matches ts
    '''
    logging.debug("[+] In getReplyByTimestamp(): %s", reps)
    for reply in reps:
        if ts == reply[O_TUP]:
            return reply

    #If we didn't get a reply for that timestamp, 
    #return none
    return None

def getRequestByType(type_, reqs):
    '''
    getRequestByType
    @params, type_ -- a ts request type number
    REQ_STANDARD = 0
    REQ_BAD_CLOCK = 1
    REQ_BAD_CHECKSUM = 2
    REQ_DUPLICATE_TS = 3
    REQ_BAD_REQUEST = -1
    reqs -- a list of timestamp requests
    Given a list of timestamp requests,
    returns the tuple whose type matches type_ 
    '''
    logging.debug("[+] In getRequestByType(): %s", reqs)
    for req in reqs:
        if type_ == req[TYPE_TUP]:
            return req
   
    logging.warn("Uh-oh. Made it to an impossible point in the code")
    sys.exit(1)

def parseLine(l, requests, replies):
    '''
    parseLine
    separates a csv line into its constituent members,
    adds the resulting timestamp tuple into requests or replies as appropriate
    @params:
    l - a line from the file, a string
    requests - a list of timestamp request tuples
    replies - a list of timestamp reply tuples
    @return: None
    '''

    epoch_time = float(l[EPOCH_TS])
    icmp_type = int(l[TS_TYPE])
    ip = l[IP_ADDR]
    origin = int(l[O_TS])
    rx = int(l[RX_TS])
    tx = int(l[TX_TS])
    reqrep_type = int(l[REQREP_TYPE])

    #either an errorred request or 
    #reply. either way, bail out now``
    if reqrep_type < 0:
        return None

    if icmp_type == TIMESTAMP_REQUEST:
        requests.append(tuple([epoch_time, origin, rx, tx, reqrep_type]))

    elif icmp_type == TIMESTAMP_REPLY:
        replies.append(tuple([epoch_time, origin, rx, tx, reqrep_type]))

    return None

def processIP(ip, reqs, reps):
    '''
    processIP
    finds the fingerprint for the IP and timestamp requests/replies
    associated with it. Calls classify, then adds fingerprint returned by
    classify to the fingerprints dict
    @params: ip, a string in dotted decimal format
    reqs, a list of timestamp request tuples 
    reps, a list of timestamp reply tuples
    @return: None
    '''
    fprint = classify(reqs, reps)
    if not fprint:
        return

    if not fprint in fingerprints:
        fingerprints[fprint] = [ip]
    else:
        fingerprints[fprint].append(ip)
    
    return None

def do_work(f):
    '''
    do_work
    this is really the mainloop, but want to have both
    the gzip open and regular open point here, so here it is
    @param: f, an open file descriptor
    @return: none
    '''
    requests = []
    replies = []
    CURRENT_IP = ""

    for line in f:
        #peek at what the ip is
        l = line.strip().split(',')
        this_ip = l[IP_ADDR]

        #case 1
        #encountered a new ip
        #reset state
        if CURRENT_IP != this_ip:
            if CURRENT_IP:
                processIP(CURRENT_IP, requests, replies)
                requests, replies = [], []
            CURRENT_IP = this_ip
        #case 2
        #otherwise, this is the same destination
        #so, add it to our current state
        parseLine(l, requests, replies)

    #Handle that last IP
    processIP(CURRENT_IP, requests, replies)

    #Deuces
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True, help="input timestamps")
    parser.add_argument("-w", "--writestats", default=False, action='store_true', help="write stats")
    parser.add_argument("-o", "--output", required=False, help="write per-IP classification")
    parser.add_argument("-v", "--verbose", default=False, action='store_true', help="verbose debugging")
    parser.add_argument("-s", "--sortinput", default=True, action='store_true', help="sort input")
    args = parser.parse_args()

    if (args.verbose):
        logging.getLogger().setLevel(logging.DEBUG)

    fd = None
    try:
        fd = gzip.open(args.input)
        fd.read(1)
        fd = gzip.open(args.input)
    except IOError, e:
        fd = open(args.input)

    if args.sortinput:
        indata = fd.readlines()
        sorted_indata = sorted(indata, key=lambda x: x.split(',')[2])
        do_work(sorted_indata)
    else:
        do_work(fd)

    logging.info("\n[+] Catgories:")
    printStats(results)
    if args.writestats:
        writeStats(results, "categories.stats")

    logging.info("\n[+] Timezones:")
    printStats(timezones)
    if args.writestats:
        writeStats(timezones, "timezones.stats")

    if args.writestats:
        logging.info("\n[+] Fingerprints:")
        writeFingerprints(fingerprints,'fingerprints.stats')

    if args.output:
        logging.info("\n[+] Wrote per-IP classification: %s", args.output)
        writeClassifications(fingerprints, args.output)
