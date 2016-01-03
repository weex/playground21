# Copyright (C) 2013-2015 The python-bitcoinlib developers
# Copyright (C) 2016 David Sterry
#
# This file is modified from a file in python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from __future__ import absolute_import, division, print_function, unicode_literals

from bitcoin.wallet import CBitcoinSecret
from bitcoin.signmessage import BitcoinMessage, VerifyMessage, SignMessage

def sign(key, message):
    key = CBitcoinSecret(key)
    message = BitcoinMessage(message)
    return SignMessage(key, message).decode('ascii')

def verify(address, message, signature):
    message = BitcoinMessage(message)
    return VerifyMessage(address, message, signature)
