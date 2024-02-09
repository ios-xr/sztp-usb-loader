import base64
import hashlib
import json
import os
from urllib.parse import urlunparse

from . import util
#Internal
from .crypto import CMS, PKCS7, getCertificates
from .exceptions import *

CONFIG_FILE = 'configuration-file'
PRE_CONFIG = 'pre-configuration-script-file'
POST_CONFIG = 'post-configuration-script-file'
CONFIG_HANDLE = 'configuration-handling'
BOOT_IMAGE = 'boot-image'
OS_NAME = 'os-name'
OS_VERSION = 'os-version'
DOWNLOAD_URI = 'download-uri'
IMG_VERIFICATION = 'image-verification'
CONFIG_MERGE = 'merge'
CONFIG_REPLACE = 'replace'
CONVEYED_INFO = 'conveyed-information'
OWNER_CERT = 'owner-certificate'
OWNERSHIP_VOUCHER = 'ownership-voucher'


class _Base64:
    @classmethod
    def encode(cls, data):
        if data is None:
            return None

        if isinstance(data, str):
            data = data.encode()

        return base64.b64encode(data).decode('utf-8')

    @classmethod
    def encodeFile(cls, fileName):
        if not fileName:
            return None
        with open(fileName, 'rb') as f:
            encData = base64.b64encode(f.read()).decode('utf-8')

        return encData


OI = 'OI'


# TODO: Figure out a better name for this class
class ProvisioningData:
    def __init__(self,
                 configHandle=None,
                 preConfigScript=None,
                 configuration=None,
                 postConfigScript=None,
                 osName=None,
                 osVersion=None,
                 imagePath=None,
                 hashAlg='sha-256',
                 usbRootDirs=None):
        self.bootImage = None
        if imagePath:
            self.bootImage = Image(osName=osName,
                                   osVersion=osVersion,
                                   paths=imagePath,
                                   hashAlg=hashAlg,
                                   rootPath=usbRootDirs)

        self.configHandle = configHandle
        self.preConfigScript = preConfigScript
        self.postConfigScript = postConfigScript
        self.configuration = configuration


class BootstrapData:
    def __init__(self, pd=None, oc=None, ov=None, certificates=None, bootable=False, genActions=False):
        self.ci = None
        self.pd = pd
        self.certificates = certificates
        self.bootable = bootable
        self.genActions = genActions
        self.oi = OnboardingInformation(
            bootImage=self.pd.bootImage,
            configHandle=self.pd.configHandle,
            preConfigScript=self.pd.preConfigScript,
            configFile=self.pd.configuration,
            postConfigScript=self.pd.postConfigScript,
            config=self.pd.configuration)
        self.ci = self._prepareOI()
        self.actions = self._prepareActions()

        self.ownerCertificate = OwnerCertificate(cert=oc)
        self.oc = self._prepareOC()
        self.ownershipVoucher = OwnershipVoucher(voucher=ov)
        self.ov = self._prepareOV()

    def _prepareActions(self):
        if self.bootable or self.genActions:
            actionDict = {'actions':{}}
            actionDict['actions']['reload-bootmedia-usb'] = True
            actionData = json.dumps(actionDict)
            actionData = self._cmsEncode(actionData, sign=True)
        else:
            actionData = None
        return actionData

    def _prepareOI(self):
        data = json.dumps(self.oi.serialize())
        data = self._cmsEncode(data, sign=True)

        return data

    def _prepareOC(self):
        degenerateData = PKCS7.createDegenerateForm(self.ownerCertificate.cert)

        return degenerateData

    def _prepareOV(self):
        if not self.ownershipVoucher.voucher:
            return None

        return self.ownershipVoucher.voucher

    def _cmsEncode(self, data, sign=True, encrypt=False):
        try:
            cmsData = CMS(data, self.certificates)
        except CryptoError as e:
            raise e from None

        cert = None
        key = None

        if sign:
            cmsData.sign(key, cert, CMS.DER_ENCODING)
        else:
            cmsData.create(outform=CMS.DER_ENCODING)

        if encrypt:
            cmsData.encrypt(cert=self.configIni.encryptCert,
                            inform=CMS.DER_ENCODING,
                            outform=CMS.DER_ENCODING)

        return cmsData.data

    def serialize(self):
        d = {"{}".format(CONVEYED_INFO): self.ci}

        if self.ov:
            d["{}".format(OWNERSHIP_VOUCHER)] = self.ov

        if self.oc:
            d["{}".format(OWNER_CERT)] = self.oc

        return d

    def __str__(self):
        return json.dumps(self.serialize())


class OwnerCertificate:
    def __init__(self, cert=None):
        self._certPath = cert
        self.cert = self._getCert()

    def _getCert(self):
        if not self._certPath or self._certPath.strip() == '':
            return None

        with open(self._certPath, 'r') as cert:
            return cert.read()


class OwnershipVoucher:
    def __init__(self, voucher=None):
        self._voucherPath = voucher
        self.voucher = self._getVoucher()

    def _getVoucher(self):
        if not self._voucherPath or self._voucherPath.strip() == '':
            return None

        with open(self._voucherPath, 'rb') as f:
            return f.read()


class Image:
    def __init__(self,
                 osName=None,
                 osVersion=None,
                 paths=None,
                 hashAlg=None,
                 rootPath=None):
        self.OSName = osName
        self.OSVersion = osVersion
        self._paths = paths
        self._rootPaths = rootPath
        self.imageUrls = self._createFileURI()
        self.hashAlg = hashAlg
        _hashMethod = self._gethashAlg(self.hashAlg)
        self.imgHash = [util.genHash(i, _hashMethod) for i in self._paths['src']]

    def _createFileURI(self):
        if not self._rootPaths:
            return self._paths

        imgPaths = list()
        for image in self._paths['dest']:
            for root in self._rootPaths:
                fullPath = os.path.join(root, image)
                url = urlunparse(("file", "", fullPath, "", "", ""))
                imgPaths.append(url)

        return imgPaths

    def _gethashAlg(self, alg):
        """
        Creates hashlib object based on algorithm mentioned

        : param alg
            Algorithm based on which hash should be generated
        """
        if '-' in alg:
            alg = alg.split(':')[-1].replace('-', '')

        if alg not in hashlib.algorithms_guaranteed:
            return None

        supportedHash = {'sha256': hashlib.sha256, 'sha384': hashlib.sha384}

        try:
            return supportedHash[alg]
        except:
            return None

    def serialize(self):
        # Compute hashes of the images in self._paths and repeat each of them same times
        # as the number of root directories
        # eg: if there are two images(image1.iso and image2.iso), self._rootPaths = ['/disk2:', '/disk3:]
        #     imageVerification = [hash1, hash1, hash2, hash2]
        imageVerification = [{
            'hash-algorithm': 'ietf-sztp-conveyed-info:{}'.format(self.hashAlg),
            'hash-value': util.genHash(i)
        } for i in self._paths['src'] for _ in self._rootPaths]

        bi = {
            "os-name": self.OSName,
            "os-version": self.OSVersion,
            "download-uri": self.imageUrls,
            "image-verification": imageVerification,
        }

        return bi


class OnboardingInformation:
    def __init__(self,
                 bootImage=None,
                 configHandle=CONFIG_MERGE,
                 preConfigScript=None,
                 configFile=None,
                 postConfigScript=None,
                 config=None):
        self.bootImage = bootImage
        self.configHandle = configHandle
        self.preConfigScript = _Base64.encodeFile(preConfigScript)
        self.config = _Base64.encodeFile(configFile)
        self.postConfigScript = _Base64.encodeFile(postConfigScript)
        self._config = config

    def serialize(self):
        oi = dict()
        if self.bootImage is not None:
            oi['boot-image'] = self.bootImage.serialize()
        oi.update({
            "configuration-handling": self.configHandle,
            "pre-configuration-script": self.preConfigScript,
            "configuration": self.config,
            "post-configuration-script": self.postConfigScript,
        })

        return {"ietf-sztp-conveyed-info:onboarding-information": oi}

    def __str__(self):
        return json.dumps(self.serialize())
