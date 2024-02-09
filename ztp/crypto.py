import json
import os

from . import util
from ._cms import _CMS, _CRL2PKCS7, _PKCS7, CMSType, _ContentType
from .exceptions import *


class CMS:
    DER_ENCODING = 'DER'
    SMIME_ENCODING = 'S/MIME'

    def __init__(self, data, certificates, encoding=SMIME_ENCODING):
        self.data = data
        self.encoding = encoding
        self.certificates = certificates

        self._cms = _CMS()
        self._oid = _ContentType()

        self.contentType = None

    def _updateContentType(self):
        self.contentType = self._oid.getContentType(cmsData=self.cmsout())

    def create(self, outform=SMIME_ENCODING):
        self.data = self._cms.dataCreate(data=self.data.encode(),
                                         outform=outform)
        return self

    def encode(self, encoding=DER_ENCODING):
        self.data = self._cms.encode(data=self.data, encoding=encoding)
        return self

    def sign(self, privateKey=None, cert=None, outform=SMIME_ENCODING):
        if privateKey is None:
            privateKey = self.certificates.ownerPrivateKey
        if cert is None:
            cert = self.certificates.ownerCert
        self.data = self._cms.sign(data=self.data.encode(),
                                   inkey=privateKey,
                                   signer=cert,
                                   outform=outform)
        return self

    def decode(self, inform=DER_ENCODING, outform=SMIME_ENCODING):
        self.data = self._cms.decode(data=self.data,
                                     inform=inform,
                                     outform=outform)
        return self

    def verify(self, cafile=None, certfile=None):
        if not cafile:
            cafile = self.certificates.ownerRootCert
        if not certfile:
            certfile = self.certificates.ownerCert

        self.data = self._cms.verify(data=self.data,
                                     cafile=cafile,
                                     certfile=certfile)
        return self

    def encrypt(self, cert=None, inform=SMIME_ENCODING, outform=SMIME_ENCODING):
        if not cert:
            cert = self.certificates.sudiPubCert

        self.data = self._cms.encrypt(data=self.data,
                                      cert=cert,
                                      inform=inform,
                                      outform=outform)
        return self

    def decrypt(self, inkey, recip):
        if None in (inkey, recip):
            raise CryptoError(ErrorCode.INVALID_CERTIFICATE)
        self.data = self._cms.decrypt(data=self.data, inkey=inkey, recip=recip)
        return self

    def _toDict(self):
        try:
            self.data = json.loads(self.data)
        except ValueError:
            pass

        return self.data

    def extractEnvelopedData(self, inform=SMIME_ENCODING):
        self.data = self._cms.extractEnvelopedData(data=self.data,
                                                   inform=inform)
        self.data = self.data.decode()

        return self

    def cmsout(self):
        return self._cms.cmsout(self.data)

    def getContentType(self):
        return self._oid.getContentType(self.cmsout())

    def isSigned(self):
        return self.getContentType() == CMSType.SIGNED


def getCertificates():
    certsRootPath = 'certificates'

    ownerCertPath = 'certificates/owner/owner.cert'
    ownerPrivatePemPath = 'certificates/owner/owner_private.pem'
    ownerRootCertPath = os.path.join(certsRootPath, 'owner/root.cert')
    ownerRootKeyPath = os.path.join(certsRootPath, 'owner/root.key')

    tlsCertPath = os.path.join(certsRootPath, 'tls/ztp-server.com.crt')
    tlsPrivatePemPath = os.path.join(certsRootPath, 'tls/ztp-server.com.pem')

    sudiCertPath = os.path.join(certsRootPath, 'sudi/sudi.cert')
    sudiPublicPemPath = os.path.join(certsRootPath, 'sudi/sudi_public.pem')

    ciscoCertPath = os.path.join(certsRootPath, 'cisco/cisco_cert.pem')
    ciscoPrivatePemPath = os.path.join(certsRootPath, 'cisco/cisco_private.pem')

    certificates = util.AttrDict()

    certificates.ownerCert = ownerCertPath
    certificates.ownerPrivateKey = ownerPrivatePemPath
    certificates.ownerRootCert = ownerRootCertPath
    certificates.ownerRootKey = ownerRootKeyPath

    certificates.tlsCert = tlsCertPath
    certificates.tlsPrivatePem = tlsPrivatePemPath

    certificates.sudiPubCert = sudiCertPath
    certificates.sudiPrivatePem = sudiPublicPemPath

    # Dummy Cisco Certificates
    certificates.CiscoPubCert = ciscoCertPath
    certificates.CiscoPrivatePem = ciscoPrivatePemPath

    return certificates


class PKCS7:
    @staticmethod
    def createDegenerateForm(certChain):
        """
        Creates PKCS7 degenerate form
        :param certChain: X509 certificate chain in PEM encoding
        :return: Degenerate form CMS data in DER encoding
        """
        return _CRL2PKCS7.pkcs7(certChain)

    @staticmethod
    def extractX509Certs(data):
        """
        Extract X509 certs in PEM encoding
        : param data : Cert in PKCS7 format as string
        : return : Certificate in PEM encoding
        """
        return _PKCS7.getCerts(data)


class X509:
    @staticmethod
    def isValid(cert, encoding):
        cmd = ['openssl', 'x509', '-in', cert, '-inform', encoding, '-noout']
        err, _ = util.execShellCmd(cmd)
        if err:
            return err
        return None
