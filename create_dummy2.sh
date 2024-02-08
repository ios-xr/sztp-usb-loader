python3 usb.py \
        -prc testdata/pre_config_script.sh \
        -c testdata/configs.cfg \
        -psc testdata/post_config_script.sh \
        -ch merge \
        -iu dummy_usb/images/image.iso \
        -ia sha-256 \
        -oc certificates/owner.cert \
        -ocpk certificates/owner.key \
        -ov testdata/DUMMY_SN02.vcj \
        -ver 7.11.1.38I \
        -name "Cisco IOSXR" \
        -sn DUMMY_SN02 \
        -o dummy_usb

