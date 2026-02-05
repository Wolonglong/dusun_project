#! /bin/sh

GATEWAT_PROJECT_NAME=DSGW-095
GATEWAY_SOFTWARE_NAME=${GATEWAT_PROJECT_NAME}-DB11-LUCI-Openthread
VERSION=RV0.0.6
#DATA=`date +%Y%m%d`
#GATEWAY_SOFTWARE_VERSION=${GATEWAY_SOFTWARE_NAME}-${VERSION}-${DATA}
GATEWAY_SOFTWARE_VERSION=${GATEWAY_SOFTWARE_NAME}-${VERSION}
#echo $GATEWAY_SOFTWARE_VERSION
TMP_FILE="/data2/daihao/temp"

#Get the script path
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
echo "脚本所在目录：$SCRIPT_DIR"
SDK_DIR=$SCRIPT_DIR/../
echo "SDK 所在目录：$SDK_DIR"

if [ ! -d $TMP_FILE/$GATEWAT_PROJECT_NAME ]; then
	mkdir -p $TMP_FILE/$GATEWAT_PROJECT_NAME
fi

cd $SDK_DIR
# build uboot
uboot_build() {
	sudo ./build.sh uboot
	cp $SDK_DIR/u-boot/uboot.img $TMP_FILE/$GATEWAT_PROJECT_NAME
	echo ""
	ls -l $TMP_FILE/$GATEWAT_PROJECT_NAME/uboot.img
}


# build kernel
kernel_build() {
	sudo ./build.sh kernel
	cp $SDK_DIR/kernel/boot.img $TMP_FILE/$GATEWAT_PROJECT_NAME
	echo ""
	ls -l $TMP_FILE/$GATEWAT_PROJECT_NAME/boot.img
}

# build updateimg
updateimg_build() {
	sudo ./build.sh updateimg

	cp $SDK_DIR/output/update/Image/update.img $TMP_FILE/$GATEWAT_PROJECT_NAME/${GATEWAY_SOFTWARE_VERSION}.img
	echo ""
	ls -l $TMP_FILE/$GATEWAT_PROJECT_NAME/${GATEWAY_SOFTWARE_VERSION}.img
	#cp update.img -> server daihao@192.168.0.5
	#scp $SDK_DIR/output/update/Image/update.img daihao@192.168.0.5:/mnp/public/dh/release/$GATEWAY_SOFTWARE_NAME/${GATEWAY_SOFTWARE_VERSION}.img
}

all_build() {
#  uboot_build
#  kernel_build
#  firmware_build
  updateimg_build
}

case $1 in
        "uboot")
                uboot_build
                ;;
        "kernel")
                kernel_build
                ;;
        "firmware")
                firmware_build
                ;;
        "updateimg")
                updateimg_build
                ;;
        *)
                all_build
                ;;
esac

