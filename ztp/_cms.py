import tempfile

from . import util
from .exceptions import *


class CMSType(Enum):
    UNENCRYPTED = 0
    ENCRYPTED = 1
    SIGNED = 2


class _ContentType:
    def __init__(self):
        _map = {
            'data': '1.2.840.113549.1.7.1',
            'signedData': '1.2.840.113549.1.7.2',
            'envelopedData': '1.2.840.113549.1.7.3',
            'signedAndEnvelopedData': '1.2.840.113549.1.7.4',
            'digestedData': '1.2.840.113549.1.7.5',
            'encryptedData': '1.2.840.113549.1.7.6',
            'authenticatedData': '1.2.840.113549.1.9.16.1.2',
            'compressedData': '1.2.840.113549.1.9.16.1.9',
            'authenticatedEnvelopedData': '1.2.840.113549.1.9.16.1.23',
        }

        self._contentType = util.AttrDict(_map)

    def getContentType(self, cmsData):
        """
        Read the CMS data and return the outermost content type
        : param cmsData : CMS structured data
        : return : CMS type
        """
        if not cmsData:
            raise DecodeError('CMS Data is empty')

        contentType = None
        for i in cmsData.split('\n'):
            if 'contentType' in i:
                contentType = i.strip()
                break

        if not contentType:
            raise CryptoError('Invalid CMS data type')

        if self._contentType.data in contentType:
            return CMSType.UNENCRYPTED

        if self._contentType.signedData in contentType:
            return CMSType.SIGNED

        # From RFC8572 envelopedData is signed and encrypted
        if self._contentType.envelopedData in contentType:
            return CMSType.ENCRYPTED

        raise CryptoError('Invalid CMS data type')


class _CMS:
    _TMP_CMS_IN = tempfile.NamedTemporaryFile(prefix='ztp-').name
    _TMP_CMS_OUT = tempfile.NamedTemporaryFile(prefix='ztp-').name

    _CMS_DATA_CREATE_CMD = 'openssl cms -data_create -in {infile} -outform {outform} -out {outfile}'

    _CMS_SIGN_CMD = 'openssl cms -sign -nodetach -binary -in {infile} -inkey {inkey} -signer {signer} -out {outfile} -outform {outform}'
    _CMS_ENCRYPT_CMD = 'openssl cms -encrypt -in {infile} -inform {inform} -binary -out {outfile} -outform {outform} {cert}'
    _CMS_ENCODE_CMD = 'openssl cms -cmsout -in {infile} -outform {encoding} -out {outfile}'

    _CMS_VERIFY_SIGN_CMD = 'openssl cms -in {infile} -verify -CAfile {cafile} -certfile {certfile} -out {outfile}'
    _CMS_DECRYPT_CMD = 'openssl cms -decrypt -in {infile} -out {outfile} -recip {recip} -inkey {inkey}'
    _CMS_DECODE_CMD = 'openssl cms -cmsout -in {infile} -inform {inform} -out {outfile} -outform {outform}'
    _CMS_CMSOUT_CMD = 'openssl cms -cmsout -in {infile} -inform {inform} -print'

    _CMS_DATA_OUT = 'openssl cms -data_out -in {infile} -inform {inform} -out {outfile}'

    _DER_ENCODING = 'DER'
    _SMIME_ENCODING = 'S/MIME'

    _DEFAULT_TIMEOUT = 10

    def _writeToCMSIn(data, f=_TMP_CMS_IN):
        util.removeFiles(files=[_CMS._TMP_CMS_IN, _CMS._TMP_CMS_OUT])
        if data is None:
            raise CryptoError(ErrorCode.INVALID_DATA)

        with open(_CMS._TMP_CMS_IN, 'wb') as cmsFile:
            cmsFile.write(data)

    def _readFromCMSOut():
        with open(_CMS._TMP_CMS_OUT, 'rb') as cmsFile:
            data = cmsFile.read()

        if data is None or data.strip() == '':
            raise CryptoError(ErrorCode.CMS_DATA_CREATION_FAILED)

        util.removeFiles(files=[_CMS._TMP_CMS_IN, _CMS._TMP_CMS_OUT])
        return data

    def dataCreate(self,
                   data,
                   outform=_SMIME_ENCODING,
                   infile=_TMP_CMS_IN,
                   outfile=_TMP_CMS_OUT):
        _CMS._writeToCMSIn(data=data)
        cmd = self._CMS_DATA_CREATE_CMD.format(outform=outform,
                                               infile=infile,
                                               outfile=outfile)
        err, _ = util.execShellCmd(cmd,
                                   shell=True,
                                   timeout=self._DEFAULT_TIMEOUT)
        if err:
            raise CryptoError(ErrorCode.CMS_DATA_CREATION_FAILED, err)

        return _CMS._readFromCMSOut()

    def sign(self,
             data,
             inkey,
             signer,
             outform=_SMIME_ENCODING,
             infile=_TMP_CMS_IN,
             outfile=_TMP_CMS_OUT):
        _CMS._writeToCMSIn(data=data)
        cmd = self._CMS_SIGN_CMD.format(infile=infile,
                                        inkey=inkey,
                                        signer=signer,
                                        outform=outform,
                                        outfile=outfile)
        err, _ = util.execShellCmd(cmd,
                                   shell=True,
                                   timeout=self._DEFAULT_TIMEOUT)
        if err:
            raise CryptoError(ErrorCode.DATA_SIGNING_FAILED, err)

        return _CMS._readFromCMSOut()

    def verify(self,
               data,
               cafile,
               certfile,
               infile=_TMP_CMS_IN,
               outfile=_TMP_CMS_OUT):
        _CMS._writeToCMSIn(data=data)
        cmd = self._CMS_VERIFY_SIGN_CMD.format(cafile=cafile,
                                               certfile=certfile,
                                               infile=infile,
                                               outfile=outfile)
        err, _ = util.execShellCmd(cmd,
                                   shell=True,
                                   timeout=self._DEFAULT_TIMEOUT)
        if err:
            raise CryptoError(ErrorCode.SIGNATURE_VERIFICATION_ON_DATA_FAILED,
                              err)

        return _CMS._readFromCMSOut()

    def encrypt(self,
                data,
                cert,
                infile=_TMP_CMS_IN,
                outfile=_TMP_CMS_OUT,
                inform=_DER_ENCODING,
                outform=_DER_ENCODING):
        _CMS._writeToCMSIn(data=data)
        cmd = self._CMS_ENCRYPT_CMD.format(infile=infile,
                                           inform=inform,
                                           outfile=outfile,
                                           outform=outform,
                                           cert=cert)
        err, _ = util.execShellCmd(cmd,
                                   shell=True,
                                   timeout=self._DEFAULT_TIMEOUT)
        if err:
            raise CryptoError(ErrorCode.DATA_ENCRYPTION_FAILED, err)

        return _CMS._readFromCMSOut()

    def decrypt(self,
                data,
                inkey,
                recip,
                infile=_TMP_CMS_IN,
                outfile=_TMP_CMS_OUT):
        _CMS._writeToCMSIn(data=data)
        cmd = self._CMS_DECRYPT_CMD.format(recip=recip,
                                           inkey=inkey,
                                           infile=infile,
                                           outfile=outfile)
        err, _ = util.execShellCmd(cmd,
                                   shell=True,
                                   timeout=self._DEFAULT_TIMEOUT)
        if err:
            raise CryptoError(ErrorCode.DATA_DECRYPTION_FAILED, err)

        return _CMS._readFromCMSOut()

    def encode(self,
               data,
               encoding=_DER_ENCODING,
               infile=_TMP_CMS_IN,
               outfile=_TMP_CMS_OUT):
        _CMS._writeToCMSIn(data=data)
        cmd = self._CMS_ENCODE_CMD.format(encoding=encoding,
                                          infile=infile,
                                          outfile=outfile)
        err, _ = util.execShellCmd(cmd,
                                   shell=True,
                                   timeout=self._DEFAULT_TIMEOUT)
        if err:
            raise CryptoError(ErrorCode.DATA_ENCODING_FAILED, err)

        return _CMS._readFromCMSOut()

    def decode(self,
               data,
               inform=_DER_ENCODING,
               outform=_SMIME_ENCODING,
               infile=_TMP_CMS_IN,
               outfile=_TMP_CMS_OUT):
        _CMS._writeToCMSIn(data=data)
        cmd = self._CMS_DECODE_CMD.format(infile=infile,
                                          outfile=outfile,
                                          inform=inform,
                                          outform=outform)
        err, _ = util.execShellCmd(cmd,
                                   shell=True,
                                   timeout=self._DEFAULT_TIMEOUT)
        if err:
            raise CryptoError(ErrorCode.DATA_ENCODING_FAILED, err)

        return _CMS._readFromCMSOut()

    def extractEnvelopedData(self,
                             data,
                             inform=_SMIME_ENCODING,
                             infile=_TMP_CMS_IN,
                             outfile=_TMP_CMS_OUT):
        _CMS._writeToCMSIn(data=data)
        cmd = self._CMS_DATA_OUT.format(inform=inform,
                                        infile=infile,
                                        outfile=outfile)
        err, _ = util.execShellCmd(cmd,
                                   shell=True,
                                   timeout=self._DEFAULT_TIMEOUT)
        if err:
            raise CryptoError(ErrorCode.CMS_DATA_EXTRACTION_FAILED, err)

        return _CMS._readFromCMSOut()

    def cmsout(self, data, inform=_SMIME_ENCODING, infile=_TMP_CMS_IN):
        _CMS._writeToCMSIn(data=data)
        cmd = self._CMS_CMSOUT_CMD.format(inform=inform, infile=infile)
        err, out = util.execShellCmd(cmd,
                                     shell=True,
                                     timeout=self._DEFAULT_TIMEOUT)
        if err:
            raise CryptoError(ErrorCode.INVALID_DATA, err)

        return out


class _CRL2PKCS7:
    @staticmethod
    def pkcs7(cert, outform='DER'):
        certFile = tempfile.NamedTemporaryFile(prefix='ztp-').name
        with open(certFile, 'w') as f:
            f.write(cert)
        cmd = [
            'openssl', 'crl2pkcs7', '-nocrl', '-certfile', certFile, '-outform',
            outform, '-out', _CMS._TMP_CMS_OUT
        ]
        err, _ = util.execShellCmd(cmd,
                                   shell=False,
                                   timeout=_CMS._DEFAULT_TIMEOUT)
        util.removeFiles([certFile])
        if err:
            raise CryptoError(ErrorCode.INVALID_DATA, err)

        return _CMS._readFromCMSOut()


class _PKCS7:
    @staticmethod
    def getCerts(data, inform='DER'):
        certFile = tempfile.NamedTemporaryFile(prefix='ztp-').name
        with open(certFile, 'wb') as f:
            f.write(data)
        cmd = [
            'openssl', 'pkcs7', '-in', certFile, '-inform', inform,
            '-print_certs'
        ]
        err, out = util.execShellCmd(cmd, timeout=_CMS._DEFAULT_TIMEOUT)
        util.removeFiles([certFile])
        if err:
            raise CryptoError(ErrorCode.INVALID_DATA, err)

        return out
