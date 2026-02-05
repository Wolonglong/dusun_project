#! /bin/sh

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
#echo "脚本所在目录：$SCRIPT_DIR"

PROJECT_BIN="$SCRIPT_DIR/common/scripts/"
#echo "$PROJECT_BIN"

export PATH=$PATH:$PROJECT_BIN
