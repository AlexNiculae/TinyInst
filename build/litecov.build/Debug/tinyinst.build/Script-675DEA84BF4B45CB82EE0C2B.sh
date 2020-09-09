#!/bin/sh
make -C /Users/aniculae/Documents/TinyInst/build -f /Users/aniculae/Documents/TinyInst/build/CMakeScripts/tinyinst_cmakeRulesBuildPhase.make$CONFIGURATION OBJDIR=$(basename "$OBJECT_FILE_DIR_normal") all
