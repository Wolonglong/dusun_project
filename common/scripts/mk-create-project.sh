#! /bin/sh
# create project
# Usage: ./mk-create_project.sh Project_Name

#Get the script path
#SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
#echo "脚本所在目录：$SCRIPT_DIR"

PROJECT_ALL_DIR=$SCRIPT_DIR/../../project_all
#echo "project_all 所在目录：$PROJECT_ALL_DIR"

PROJECT_NAME="$1"

if [[ -z "$PROJECT_NAME" ]]; then
	echo "Usage: $0 Project_Name"
	echo ""
	ls $PROJECT_ALL_DIR
	exit 1
fi

if [ -d $PROJECT_ALL_DIR/$PROJECT_NAME ]; then 
	echo "Error: Project exists."
	echo ""
	echo  $PROJECT_ALL_DIR/$PROJECT_NAME 
else
	mkdir -p $PROJECT_ALL_DIR/$PROJECT_NAME
	mkdir -p $PROJECT_ALL_DIR/$PROJECT_NAME/apps/
	touch $PROJECT_ALL_DIR/$PROJECT_NAME/readme.txt
	echo ""
	echo "Project '$PROJECT_NAME' structure created successfully."
fi

echo ""
ls $PROJECT_ALL_DIR
