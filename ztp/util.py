import base64
import hashlib
import os
import subprocess
from contextlib import suppress

from .exceptions import *


def genHash(fileName, hashAlg=None):
    BUF_SIZE = 65536  # lets read stuff in 64kb chunks!

    if hashAlg is not None:
        sha = hashAlg()
    else:
        sha = hashlib.sha256()

    with open(fileName, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break

            sha.update(data)
    hashValue = sha.hexdigest()
    # Convert hash value to RFC 8572 (Section 6.3) compliant format
    # References: hex-string - RFC 6991 (Section 3)
    hashValue = ':'.join([ hashValue[i:i+2] for i in range(0, len(hashValue), 2)])
    return hashValue


def writeToFile(data, f):
    if not data:
        raise Error('No data to write')

    if isinstance(data, str):
        data = data.encode()

    with open(f, 'wb') as fp:
        fp.write(data)


def readFromFile(f):
    with open(f, 'rb') as fp:
        return fp.read()


def execShellCmd(cmd,
                 shell=False,
                 inp=None,
                 timeout=None,
                 env=None,
                 executable=None,
                 stdout=subprocess.PIPE,
                 stderr=subprocess.PIPE):
    error = None
    try:
        p = subprocess.run(cmd,
                           shell=shell,
                           env=env,
                           executable=executable,
                           stdout=stdout,
                           stderr=stderr,
                           timeout=timeout,
                           input=inp,
                           check=False)
    except subprocess.TimeoutExpired as e:
        return Exception(e)
    except subprocess.SubprocessError as e:
        return Exception(e)

    o = p.stdout
    e = p.stderr
    o = o.decode().strip() if o else ''
    e = e.decode().strip() if e else ''
    if p.returncode != 0:
        if not e:
            e = 'Unknown error occurred with output: %s' % o
        error = Exception('{} occured while executing command {}'.format(
            e, str(cmd)))

    return error, o


def removeFiles(directory=None, files=None):
    if directory and os.path.exists(directory):
        _files = (os.path.join(directory, fileName)
                  for fileName in os.listdir(directory))
    elif files:
        _files = files
    else:
        return

    for path in _files:
        try:
            os.remove(path)
        except OSError:
            pass


def createDir(dirname):
    if not os.path.isdir(dirname):
        os.makedirs(dirname)


def fileExists(path):
    if os.path.isfile(path):
        return True

    return False


class Base64:
    def encode(data):
        b64Data = base64.b64encode(data)
        return b64Data.decode()


def removeFiles(files):
    for f in files:
        with suppress(FileNotFoundError):
            os.remove(f)


class AttrDict(dict):
    def __setattr__(self, attr, value):
        self[attr] = value

    def __getattr__(self, attr):
        try:
            return self[attr]
        except KeyError:
            raise AttributeError(attr) from None

    def __delattr__(self, attr):
        try:
            del self[attr]
        except KeyError:
            raise AttributeError(attr) from None

    def __dir__(self):
        return list(self) + dir(dict) + self.keys()
