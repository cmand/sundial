import struct
import logging

def swap(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]

HOUR_MILLISECONDS = 1000 * 60 * 60 
DAY_MILLISECONDS = 1000 * 60 * 60 * 24
DAY_SECONDS = 60 * 60 * 24
MIN_NONUTC = 2 ** 31
ERROR_MARGIN = 1000 * .2

#timestamp types
TIMESTAMP_REQUEST = 13
TIMESTAMP_REPLY = 14

#common field indices
EPOCH_TS = 0
TS_TYPE = 1
IP_ADDR = 2
O_TS = 3
RX_TS = 4
TX_TS = 5
REQ_TYPE = 6
REQREP_TYPE = 6
REP_TYPE = 6

#tuple indices
TIME_TUP = 0
O_TUP = 1
RX_TUP = 2
TX_TUP = 3
TYPE_TUP = 4

#request-specific types
REQ_STANDARD = 0
REQ_BAD_CLOCK = 1
REQ_BAD_CHECKSUM = 2
REQ_DUPLICATE_TS = 3
REQ_BAD_REQUEST = -1


#reply-specific types
REP_BAD_CLOCK = 1
REP_VALID_REPLY = 0
REP_BAD_REPLY = -1

#Return status codes
BOTH = 1
RX_ONLY = 2
TX_ONLY = 3

CURRENT_IP = ""

results = {
    'normal' : 0,
    'lazy' : 0,
    'checksumLazy' : 0,
    'stuck' : 0, 
    'stuckRx' : 0,
    'stuckTx' : 0,
    'stuck0' : 0,
    'stuck0Rx' : 0,
    'stuck0Tx' : 0,
    'stuck1' : 0,
    'stuck1Rx' : 0,
    'stuck1Tx' : 0,
    'stuckLE1' : 0,
    'stuckLE1Rx' : 0,
    'stuckLE1Tx' : 0,
    'echo' : 0,
    'echoRx' : 0,
    'echoTx' : 0,
    'reflect' : 0,
    'reflectRx' : 0,
    'reflectTx' : 0,
    'timezone' : 0,
    'timezoneRx' : 0,
    'timezoneTx' : 0,
    'total' : 0,
    'correct' : 0,
    'correctRx' : 0,
    'correctTx' : 0,
    'correctLE' : 0,
    'correctLERx' : 0,
    'correctLETx' : 0,
    'correctMSB' : 0,
    'correctMSBRx' : 0,
    'correctMSBTx' : 0,
    'msb' : 0,
    'msbRx' : 0,
    'msbTx' : 0,
    'buggy' : 0, 
    'millisecond': 0,
    'millisecondRx':0,
    'millisecondTx':0,
    'second':0,
    'secondRx':0,
    'secondTx':0,
    'epoch':0,
    'epochRx':0,
    'epochTx':0
        }

#fingerprint tuple fields
NORMAL = 0
LAZY = 1
CHECKSUMLAZY = 2
STUCK = 3  
STUCKRX = 4 
STUCKTX = 5
STUCK0 = 6
STUCK0RX = 7
STUCK0TX  = 8
STUCK1 = 9
STUCK1RX  = 10
STUCK1TX  = 11
STUCKLE1  = 12
STUCKLE1RX  = 13
STUCKLE1TX  = 14
ECHO  = 15
ECHORX  = 16
ECHOTX  = 17
REFLECT  = 18
REFLECTRX = 19
REFLECTTX = 20
TIMEZONE = 21
TIMEZONERX  = 22
TIMEZONETX  = 23
CORRECT = 24
CORRECTRX = 25
CORRECTTX = 26
CORRECTLE = 27
CORRECTLERX = 28
CORRECTLETX = 29
CORRECTMSB  = 30
CORRECTMSBRX = 31
CORRECTMSBTX = 32
MSB = 33
MSBRX = 34
MSBTX = 35
BUGGY = 36
MS = 37
MSRX = 38
MSTX = 39
S = 40
SRX = 41
STX = 42
EPOCH = 43
EPOCHRX = 44
EPOCHTX = 45

fingerNames = [
    'normal',
    'lazy',
    'checksumLazy',
    'stuck', 
    'stuckRx',
    'stuckTx',
    'stuck0',
    'stuck0Rx',
    'stuck0Tx',
    'stuck1',
    'stuck1Rx',
    'stuck1Tx',
    'stuckLE1',
    'stuckLE1Rx',
    'stuckLE1Tx',
    'echo',
    'echoRx',
    'echoTx',
    'reflect',
    'reflectRx',
    'reflectTx',
    'timezone',
    'timezoneRx',
    'timezoneTx',
    'correct',
    'correctRx',
    'correctTx',
    'correctLE',
    'correctLERx',
    'correctLETx',
    'correctMSB',
    'correctMSBRx',
    'correctMSBTx',
    'msb',
    'msbRx',
    'msbTx',
    'buggy', 
    'millisecond',
    'millisecondRx',
    'millisecondTx',
    'second',
    'secondRx',
    'secondTx',
    'epoch',
    'epochRx',
    'epochTx'
        ]


timezones = { } 
fingerprints = {}
CONSTANTS = [0,1,swap(1)]
