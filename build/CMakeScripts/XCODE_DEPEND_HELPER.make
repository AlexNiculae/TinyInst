# DO NOT EDIT
# This makefile makes sure all linkable targets are
# up-to-date with anything they link to
default:
	echo "Do not invoke directly"

# Rules to remove targets that are older than anything to which they
# link.  This forces Xcode to relink the targets from scratch.  It
# does not seem to check these dependencies itself.
PostBuild.litecov.Debug:
PostBuild.tinyinst.Debug: /Users/aniculae/Documents/TinyInst/build/Debug/litecov
/Users/aniculae/Documents/TinyInst/build/Debug/litecov:\
	/Users/aniculae/Documents/TinyInst/build/Debug/libtinyinst.a\
	/Users/aniculae/Documents/TinyInst/build/third_party/obj/wkit/lib/libxed.a
	/bin/rm -f /Users/aniculae/Documents/TinyInst/build/Debug/litecov


PostBuild.tinyinst.Debug:
/Users/aniculae/Documents/TinyInst/build/Debug/libtinyinst.a:
	/bin/rm -f /Users/aniculae/Documents/TinyInst/build/Debug/libtinyinst.a


PostBuild.litecov.Release:
PostBuild.tinyinst.Release: /Users/aniculae/Documents/TinyInst/build/Release/litecov
/Users/aniculae/Documents/TinyInst/build/Release/litecov:\
	/Users/aniculae/Documents/TinyInst/build/Release/libtinyinst.a\
	/Users/aniculae/Documents/TinyInst/build/third_party/obj/wkit/lib/libxed.a
	/bin/rm -f /Users/aniculae/Documents/TinyInst/build/Release/litecov


PostBuild.tinyinst.Release:
/Users/aniculae/Documents/TinyInst/build/Release/libtinyinst.a:
	/bin/rm -f /Users/aniculae/Documents/TinyInst/build/Release/libtinyinst.a


PostBuild.litecov.MinSizeRel:
PostBuild.tinyinst.MinSizeRel: /Users/aniculae/Documents/TinyInst/build/MinSizeRel/litecov
/Users/aniculae/Documents/TinyInst/build/MinSizeRel/litecov:\
	/Users/aniculae/Documents/TinyInst/build/MinSizeRel/libtinyinst.a\
	/Users/aniculae/Documents/TinyInst/build/third_party/obj/wkit/lib/libxed.a
	/bin/rm -f /Users/aniculae/Documents/TinyInst/build/MinSizeRel/litecov


PostBuild.tinyinst.MinSizeRel:
/Users/aniculae/Documents/TinyInst/build/MinSizeRel/libtinyinst.a:
	/bin/rm -f /Users/aniculae/Documents/TinyInst/build/MinSizeRel/libtinyinst.a


PostBuild.litecov.RelWithDebInfo:
PostBuild.tinyinst.RelWithDebInfo: /Users/aniculae/Documents/TinyInst/build/RelWithDebInfo/litecov
/Users/aniculae/Documents/TinyInst/build/RelWithDebInfo/litecov:\
	/Users/aniculae/Documents/TinyInst/build/RelWithDebInfo/libtinyinst.a\
	/Users/aniculae/Documents/TinyInst/build/third_party/obj/wkit/lib/libxed.a
	/bin/rm -f /Users/aniculae/Documents/TinyInst/build/RelWithDebInfo/litecov


PostBuild.tinyinst.RelWithDebInfo:
/Users/aniculae/Documents/TinyInst/build/RelWithDebInfo/libtinyinst.a:
	/bin/rm -f /Users/aniculae/Documents/TinyInst/build/RelWithDebInfo/libtinyinst.a




# For each target create a dummy ruleso the target does not have to exist
/Users/aniculae/Documents/TinyInst/build/Debug/libtinyinst.a:
/Users/aniculae/Documents/TinyInst/build/MinSizeRel/libtinyinst.a:
/Users/aniculae/Documents/TinyInst/build/RelWithDebInfo/libtinyinst.a:
/Users/aniculae/Documents/TinyInst/build/Release/libtinyinst.a:
/Users/aniculae/Documents/TinyInst/build/third_party/obj/wkit/lib/libxed.a:
