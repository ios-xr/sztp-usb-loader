# Standard
import argparse
import os
import shutil

# from ztp.crypto import CMS, X509
from ztp import model, util
from ztp.const import Constants
from ztp.crypto import X509
from ztp.exceptions import Error, ErrorCode

InvalidOV = Exception('Invalid Ownership Voucher')
InvalidSN = Exception('Invalid Serial Number')
InvalidSNFile = Exception('Invalid File Path')


class USB:
    _CI_FILE      = 'conveyed-information.cms'
    _OC_FILE      = 'owner-certificate.cms'
    _OV_FILE      = 'ownership-voucher.vcj'
    _ACTIONS_FILE = 'ztp_actions.cms'

    def __init__(self, data, certificates) -> None:
        self.data = data
        self._validate()
        self.bsd = None
        self.certificates = certificates

    def _validate(self) -> None:
        # Validate.
        # 1. data is dictionary  [x]
        # 2. File paths exists [x]
        # 3. Serial Number
        # 4. Valid Certificate
        if self.data == None:
            raise Error(errorCode=ErrorCode.INVALID_DATA, error='Data is None')
        if not isinstance(self.data, dict):
            raise Error(errorCode=ErrorCode.INVALID_DATA,
                        error='Data must be dict')

        files = [
            f for f in
            [self.data.preConfig, self.data.postConfig, self.data.config]
            if f is not None
        ]
        if len(files) == 0:
            raise Error(errorCode=ErrorCode.INVALID_DATA,
                        error='No configuration data provided')

        for f in files:
            Validate.filename(f)

        Validate.serial(self.data.serialNum)
        Validate.oc(self.data.oc)

    def create(self) -> None:
        if self.data.bootable:
            shutil.unpack_archive(self.data.bootFile, self.data.outDir)

        pd = model.ProvisioningData(configHandle=self.data.configHandle,
                                    preConfigScript=self.data.preConfig,
                                    configuration=self.data.config,
                                    postConfigScript=self.data.postConfig,
                                    osName=self.data.osName,
                                    osVersion=self.data.osVersion,
                                    imagePath=self.data.imageUrl,
                                    hashAlg=self.data.hashAlg,
                                    usbRootDirs=Constants.ROOT_DIRS)
        self.bsd = model.BootstrapData(pd=pd,
                                       oc=self.data.oc,
                                       ov=self.data.ov,
                                       certificates=self.certificates,
                                       bootable=self.data.bootable,
                                       genActions=self.data.genActions)

    def save(self) -> None:
        self.outPath = os.path.join(self.data.outDir, Constants.EN_DIR,
                                    self.data.serialNum, Constants.BSD_DIR)
        if not os.path.exists(self.outPath):
            os.makedirs(self.outPath)
        cif = os.path.join(self.outPath, Constants.CI_FILE)
        ocf = os.path.join(self.outPath, Constants.OC_FILE)
        ovf = os.path.join(self.outPath, Constants.OV_FILE)
        act = os.path.join(self.outPath, Constants.ACTIONS_FILE)

        util.writeToFile(self.bsd.ci, cif)
        util.writeToFile(self.bsd.oc, ocf)
        util.writeToFile(self.bsd.ov, ovf)
        if self.data.bootable or self.data.genActions:
            util.writeToFile(self.bsd.actions, act)

        if self.data.copyImage:
            imgPath = os.path.join(self.data.outDir, self.data.imageUrl['dest'][0])
            self.imgDest = os.path.dirname(imgPath)
            if not os.path.exists(self.imgDest):
                os.makedirs(self.imgDest)
            shutil.copyfile(self.data.imageUrl['src'][0], imgPath)
            print('Copied image to {}'.format(imgPath))

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__

        return False

    def __str__(self) -> str:
        return str(self.__dict__)

class Validate:
    @staticmethod
    def oc(cert):
        if not os.path.isfile(cert):
            raise Error(errorCode=ErrorCode.FILE_NOT_FOUND)

        ret = X509.isValid(cert, encoding='PEM')
        if ret is not None:
            raise Error(ErrorCode.X509_VERIFICATION_FAILED,
                        'Not a valid x509 PEM certificate')

    @staticmethod
    def serial(serialNum):
        if serialNum is None or serialNum == '':
            raise Error(errorCode=ErrorCode.INVALID_SERIAL_NUM)

    @staticmethod
    def filename(filePath):
        if not util.fileExists(filePath):
            raise Error(errorCode=ErrorCode.FILE_NOT_FOUND)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('-prc',
                        '--pre-config',
                        dest='preConfig',
                        help='Pre config file path')
    parser.add_argument('-c',
                        '--config',
                        dest='config',
                        help='Config file path')
    parser.add_argument('-psc',
                        '--post-config',
                        dest='postConfig',
                        help='Post config file path')
    parser.add_argument('-ch',
                        '--config-handling',
                        dest='configHandle',
                        choices=['merge', 'replace'],
                        help='Config handling merge/replace')
    parser.add_argument('-iu', '--image-url', action='append', dest='imageUrl', help='Image URL')
    parser.add_argument('-ia',
                        '--image-hash-alg',
                        dest='hashAlg',
                        help='Image Hash Alg')
    parser.add_argument('-cp',
                        '--copy-image',
                        dest='copyImage',
                        action='store_true',
                        help='Copy the image from path in --image-url to argument of --image-relative-path')
    parser.add_argument('-ip',
                        '--image-relative-path',
                        dest='imgRelPath',
                        required=False,
                        help='Relative Path in USB where image (is present / should be copied to)')
    parser.add_argument('-ver',
                        '--os-version',
                        dest='osVersion',
                        help='OS Version')
    parser.add_argument('-name',
                        '--os-name',
                        dest='osName',
                        help='OS Name')
    parser.add_argument('-oc',
                        '--owner-cert',
                        dest='oc',
                        required=True,
                        help='Path to Owner Certificate Private key')
    parser.add_argument('-ocpk',
                        '--owner-cert-pk',
                        dest='ocpk',
                        required=True,
                        help='Path to Owner Certificate')
    parser.add_argument('-ov',
                        '--ownership-voucher',
                        dest='ov',
                        required=True,
                        help='Path to Ownership Voucher')
    parser.add_argument('-o',
                        '--output',
                        dest='outDir',
                        required=True,
                        help='Output Path')
    parser.add_argument('-sn',
                        '--serial-num',
                        dest='serialNum',
                        required=True,
                        help='RP Serial Number')
    parser.add_argument('-b',
                        '--bootable',
                        dest='bootable',
                        action='store_true',
                        help='Use this flag if the input is a bootable image zip file')
    parser.add_argument('-bf',
                        '--boot-file',
                        dest='bootFile',
                        required=False,
                        help='Relative Path of Bootable ZIP file. Use this flag if the input is a bootable image zip file')
    parser.add_argument('-ga',
                        '--generate-actions',
                        dest='genActions',
                        action='store_true',
                        help='Generate signed actions file artifact with \'reload-bootmedia-usb\' set to true')

    options = parser.parse_args()
    if (vars(options)['bootable']):
        options.copyImage = False
        options.imgRelPath = 'boot/install-image.iso'
        options.imageUrl = [os.path.join(options.outDir, 'boot/install-image.iso')]

        if not vars(options)['bootFile']:
            parser.error('The --boot flag requires a valid --boot-file argument')

    if (vars(options)['copyImage'] and not vars(options)['imgRelPath']):
        parser.error('The --copyImage argument requires the --image-relative-path')


    data = util.AttrDict()
    data.preConfig = options.preConfig
    data.postConfig = options.postConfig
    data.config = options.config
    data.configHandle = options.configHandle
    data.imageUrl = options.imageUrl
    data.hashAlg = options.hashAlg
    data.osName = options.osName
    data.osVersion = options.osVersion
    data.oc = options.oc
    data.ov = options.ov
    data.serialNum = options.serialNum
    data.outDir = options.outDir
    data.bootable = options.bootable
    data.copyImage = options.copyImage
    data.imgRelPath = options.imgRelPath
    data.bootFile = options.bootFile
    data.genActions = options.genActions

    pathDict = {'src':[], 'dest':[]}
    pathDict['src'].append(data.imageUrl[0])
    if data.imgRelPath:
        dir = os.path.dirname(data.imgRelPath)
        file = os.path.basename(data.imageUrl[0])
        pathDict['dest'].append(os.path.join(dir, file))
    else:
        pathDict['dest'].append(data.imageUrl[0])
    data.imageUrl = pathDict


    certs = util.AttrDict()
    certs.ownerPrivateKey = options.ocpk
    certs.ownerCert = options.oc

    try:

        usb = USB(data=data, certificates=certs)
        usb.create()
        usb.save()
    except Error as e:
        print('Failed to generate Bootstrapping data')
        print(e)


if __name__ == '__main__':
    main()
