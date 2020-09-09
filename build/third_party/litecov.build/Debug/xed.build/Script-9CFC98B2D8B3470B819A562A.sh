#!/bin/sh
make -C /Users/aniculae/Documents/TinyInst/build/third_party -f /Users/aniculae/Documents/TinyInst/build/third_party/CMakeScripts/xed_cmakeRulesBuildPhase.make$CONFIGURATION OBJDIR=$(basename "$OBJECT_FILE_DIR_normal") all
