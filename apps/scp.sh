#! /bin/sh

if [ "$4" = "0.5" ]; then
	SERVER_ADDRESS="daihao@192.168.0.5:/mnt/public/dh/release/"
	if [ "$4"  ]; then
		if [ "$3" = "095" ]; then
			PROJECT_NAME=DSGW-095
		elif [ "$3" = "210" ]; then
			PROJECT_NAME=DSGW-210
		fi
	fi
else
	SERVER_ADDRESS="dusun@192.168.0.60:/data2/daihao/temp"
	if [ "$3" = "095" ]; then
		PROJECT_NAME=DSGW-095
		UBOOT_PARTITION="/dev/mmcblk2p1"
		BOOT_PARTITION="/dev/mmcblk2p4"
	elif [ "$3" = "210" ]; then
		PROJECT_NAME=DSGW-210
		UBOOT_PARTITION="/dev/mmcblk2p1"
		BOOT_PARTITION="/dev/mmcblk2p4"
	fi
fi

usage() {
	echo "*****************************************************************"
	echo "*Usage: 							*"
	echo "*	upload:							*"
	echo "*		scp.sh -u File.txt  				*"
	echo "*		scp.sh -u File.txt Project_Name			*"
	echo "*		scp.sh -u File.txt Project_Name Server_address	*"
	echo "*	download:						*"
	echo "*		scp.sh -d File.txt  				*"
	echo "*		scp.sh -d File.txt Project_Name			*"
	echo "*		scp.sh -d File.txt Project_Name Server_address	*"
	echo "* download uboot						*"
	echo "*		scp.sh -U boot 			 		*"
	echo "*		scp.sh -U boot Project_Name 			*"
	echo "*		scp.sh -U uboot 		 		*"
	echo "*		scp.sh -U uboot Project_Name 			*"
	echo "*								*"
	echo "*****************************************************************"
	exit 0
}

if [ -z "$1"  ] & [ -z "$2" ]; then
	usage
fi

if [ "$1" = "-u" ]; then
	scp $2 $SERVER_ADDRESS/$PROJECT_NAME
	if [ $? -eq 0 ]; then
    		echo "Upload Successful"
	else
    		echo "ERROR: Upload Failed"
	fi
	echo ""
	#echo "scp $2 $SERVER_ADDRESS/$PROJECT_NAME"
	echo "$SERVER_ADDRESS/$PROJECT_NAME/$2"
elif [ "$1" = "-d" ]; then
	scp -r $SERVER_ADDRESS/$PROJECT_NAME/$2 ./
	if [ $? -eq 0 ]; then
    		echo "Download Successful"
	else
    		echo "ERROR: Download Failed"
	fi
	echo ""
	echo "scp -r $SERVER_ADDRESS/$PROJECT_NAME/$2 ./"
elif [ "$1" = "-U" ]; then
	if [ "$2" = "uboot" ]; then
		echo ""
		scp -r $SERVER_ADDRESS/$PROJECT_NAME/uboot.img ./
		echo "$SERVER_ADDRESS/$PROJECT_NAME/uboot.img"
		if [ $? -ne 0 ]; then
			echo "ERROR: scp failed"
			echo ""
			exit 0
		fi
		#dd if=./uboot.img of=$UBOOT_PARTITION
		#sync;
		#reboot -f
	elif [ "$2" = "boot" ]; then
		echo ""
		scp -r $SERVER_ADDRESS/$PROJECT_NAME/boot.img ./
		echo "$SERVER_ADDRESS/$PROJECT_NAME/boot.img"
		if [ $? -ne 0 ]; then
			echo "ERROR: scp failed"
			echo ""
			exit 0
		fi
		#dd if=./boot.img of=$UBOOT_PARTITION
		#sync;
		#reboot -f
	else
		usage
	fi
else
	usage
fi

echo ""

