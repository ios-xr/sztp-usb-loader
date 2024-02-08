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

