
# sztp-usb-loader


Implements the tool to create the Bootstrapping data to securely provision the device using USB.
Given the USB drive is not a Trusted source of Bootstrapping data, we need to validate the contents of the USB before using it for Provisioning.
RFC8572 defines a way to verify and trust the Boostraping data from Untrusted data sources(like USB) and Securely provisioning the Device.

## Usage
```
usage: usb.py [-h] [-prc PRECONFIG] [-c CONFIG] [-psc POSTCONFIG]
              [-ch {merge,replace}] [-iu IMAGEURL] [-ia HASHALG] [-cp]
              [-ip IMGRELPATH] [-ver OSVERSION] [-name OSNAME] -oc OC -ocpk
              OCPK -ov OV -o OUTDIR -sn SERIALNUM [-b] [-bf BOOTFILE] [-ga]

optional arguments:
  -h, --help            show this help message and exit
  -prc PRECONFIG, --pre-config PRECONFIG
                        Pre config file path
  -c CONFIG, --config CONFIG
                        Config file path
  -psc POSTCONFIG, --post-config POSTCONFIG
                        Post config file path
  -ch {merge,replace}, --config-handling {merge,replace}
                        Config handling merge/replace
  -iu IMAGEURL, --image-url IMAGEURL
                        Image URL
  -ia HASHALG, --image-hash-alg HASHALG
                        Image Hash Alg
  -cp, --copy-image     Copy the image from path in --image-url to argument of
                        --image-relative-path
  -ip IMGRELPATH, --image-relative-path IMGRELPATH
                        Relative Path in USB where image (is present / should
                        be copied to)
  -ver OSVERSION, --os-version OSVERSION
                        OS Version
  -name OSNAME, --os-name OSNAME
                        OS Name
  -oc OC, --owner-cert OC
                        Path to Owner Certificate Private key
  -ocpk OCPK, --owner-cert-pk OCPK
                        Path to Owner Certificate
  -ov OV, --ownership-voucher OV
                        Path to Ownership Voucher
  -o OUTDIR, --output OUTDIR
                        Output Path
  -sn SERIALNUM, --serial-num SERIALNUM
                        RP Serial Number
  -b, --bootable        Use this flag if the input is a bootable image zip
                        file
  -bf BOOTFILE, --boot-file BOOTFILE
                        Relative Path of Bootable ZIP file. Use this flag if
                        the input is a bootable image zip file
  -ga, --generate-actions
                        Generate signed actions file artifact with 'reload-
                        bootmedia-usb' set to true
```




## Example

- Move to root folder of this repo

Device Serial #DUMMY_SN01

- Prepare the necessary data for the tool to function

- Scripts (Python or Shell)
```
sztp-usb-loader > ls -l testdata/pre_config_script.sh
-rw-------. 1 root eng 36 Feb  8 12:44 testdata/pre_config_script.sh
sztp-usb-loader > ls -l testdata/post_config_script.sh
-rw-------. 1 root eng 37 Feb  8 12:45 testdata/post_config_script.sh

```

- Configuration
```
sztp-usb-loader > ls -l testdata/configs.cfg
-rw-r--r--. 1 root eng 97 Feb  8 12:34 testdata/configs.cfg
```
- Image
```
sztp-usb-loader > ls -l testdata/image.iso
-rw-r--r--. 1 root eng 6 Feb  8 11:26 testdata/image.iso
```

- You should have OC public key and private keys
- You should have OV created. OV is created from serial number present in SUDI certificate
- Run the tool

```
python3 usb.py \
        -prc testdata/pre_config_script.py \
        -c testdata/configs.cfg \
        -psc testdata/post_config_script.py \
        -ch merge \
        -iu testdata/image.iso \
        -ia sha-256 \
        -oc certificates/owner.cert \
        -ocpk certificates/owner.key \
        -ov testdata/DUMMY_SN01.vcj \
        -ver 7.11.1.38I \
        -name "Cisco IOSXR" \
        -sn DUMMY_SN01 \
        -o dummy_usb \
        -cp \
        -ip images/
```


- Copy complete tree to USB

```
sztp-usb-loader > tree dummy_usb/
dummy_usb/
├── EN9
│   └── DUMMY_SN01
│       └── bootstrapping-data
│           ├── conveyed-information.cms
│           ├── owner-certificate.cms
│           └── ownership-voucher.vcj
└── images
    └── image.iso

4 directories, 4 files
```

- The same USB can be used to provision multiple devices if needed. Simply run the tool again with the --image-url path set to the path of existing image on the USB and skipping the --copy-image flag and --image-relative-path .
```
python3 usb.py \
        -prc testdata/pre_config_script.sh \
        -c testdata/configs.cfg \
        -psc testdata/post_config_script.sh \
        -ch merge \
        -iu dummy_usb/images/image.iso \
        -ia sha-256 \
        -oc certificates/owner.cert \
        -ocpk certificates/owner.key \
        -ov testdata/DUMMY_SN01.vcj \
        -ver 7.11.1.38I \
        -name "Cisco IOSXR" \
        -sn DUMMY_SN02 \
        -o dummy_usb
```
Directory tree of USB tool after running the tool for DUMMY_SN02
```
sztp-usb-loader > tree dummy_usb/
dummy_usb/
├── EN9
│   ├── DUMMY_SN01
│   │   └── bootstrapping-data
│   │       ├── conveyed-information.cms
│   │       ├── owner-certificate.cms
│   │       └── ownership-voucher.vcj
│   └── DUMMY_SN02
│       └── bootstrapping-data
│           ├── conveyed-information.cms
│           ├── owner-certificate.cms
│           └── ownership-voucher.vcj
└── images
    └── image.iso

6 directories, 7 files
```