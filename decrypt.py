import base64
import hashlib
import binascii
import codecs
import sys
import logging
from Cryptodome import Random
from Cryptodome.Cipher import AES
import xml.etree.ElementTree as ET
#from impacket.winregistry import hexdump

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

cryptedrecords = []
plainrecords = []
keydata = None
if len(sys.argv) < 2:
    print('usage: decrypt.py <file> [encoding]')
    sys.exit(1)

if len(sys.argv) > 2:
    encoding = sys.argv[2]
else:
    encoding = 'utf-8'

infile = codecs.open(sys.argv[1], 'r', encoding)
class LogFormatter(logging.Formatter):
  def __init__(self):
      logging.Formatter.__init__(self,'%(prefix)s%(message)s', None)

  def format(self, record):
    if record.levelno == logging.INFO:
      record.prefix = ''
    elif record.levelno == logging.DEBUG:
      record.prefix = 'DEBUG: '
    elif record.levelno == logging.WARNING:
      record.prefix = 'ERROR: '
    else:
      record.prefix = 'ERROR: '

    return logging.Formatter.format(self, record)

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(LogFormatter())
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

try:
    for line in infile:
        try:
            ltype, data = line.strip().split(': ')
        except ValueError:
            continue
        ltype = ltype.replace(u'\ufeff',u'')
        if ltype.lower() == 'record':
            xmldata, crypteddata = data.split(';')
            plainrecords.append(xmldata)
            cryptedrecords.append(crypteddata)
        if ltype.lower() == 'unencrypted key':
            keydata = base64.b64decode(data)
except UnicodeDecodeError:
    logging.error('Could not read file with the specified encoding. Please specify the encoding (utf-16-le?)')
infile.close()
if not keydata:
    logging.error('No keydata!')
    sys.exit(1)

key1 = keydata[-44:]
key2 = keydata[-88:-44]

for index, record in enumerate(cryptedrecords):
    dcrypt = base64.b64decode(record)
    # hexdump(dcrypt)
    iv = dcrypt[8:24]
    # hexdump(iv)
    cryptdata = dcrypt[24:]

    cipher = AES.new(key2[12:], AES.MODE_CBC, iv)
    drecord = unpad(cipher.decrypt(cryptdata)).decode('utf-16-le').rstrip('\x00')
    data = base64.b64decode(plainrecords[index]).decode('utf-16-le')
    ctree = ET.fromstring(drecord)
    dtree = ET.fromstring(data)
    if 'forest-login-user' in data:
        logging.info('Local AD credentials')
        el = dtree.find(".//parameter[@name='forest-login-domain']")
        if el is not None:
            logging.info('\tDomain: %s', el.text)
        el = dtree.find(".//parameter[@name='forest-login-user']")
        if el is not None:
            logging.info('\tUsername: %s', el.text)
    else:
        # Assume AAD config
        logging.info('Azure AD credentials')
        el = dtree.find(".//parameter[@name='UserName']")
        if el is not None:
            logging.info('\tUsername: %s', el.text)
    # Can be either lower or with capital P
    fpw = None
    el = ctree.find(".//attribute[@name='Password']")
    if el is not None:
        fpw = el.text
    el = ctree.find(".//attribute[@name='password']")
    if el is not None:
        fpw = el.text
    if fpw:
        logging.info('\tPassword: %s', fpw)
