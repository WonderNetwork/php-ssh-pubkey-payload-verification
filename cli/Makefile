.DEFAULT_TARGET := ../bin/ssh-verify

# we need to build outside of the root composer path
BUILD_PATH := $(shell mktemp -d)

../bin/ssh-verify: tools/box ${BUILD_PATH}/vendor
	@tools/box/vendor/bin/box compile -d "${BUILD_PATH}"
	@mv "${BUILD_PATH}/index.phar" ../bin/ssh-verify
	@rm -fr "${BUILD_PATH}"

${BUILD_PATH}/vendor:
	@cp composer.json composer.lock "${BUILD_PATH}"
	@sed s/@git-version@/$(shell git describe --tags --always HEAD)/ ssh-verify > "${BUILD_PATH}/index.php"
	@composer install -d "${BUILD_PATH}"
	@unlink ${BUILD_PATH}/vendor/wondernetwork/ssh-pubkey-payload-verification
	@mkdir ${BUILD_PATH}/vendor/wondernetwork/ssh-pubkey-payload-verification
	@cp -r ../src ../composer.json ${BUILD_PATH}/vendor/wondernetwork/ssh-pubkey-payload-verification/

tools/box: tools/box/vendor
tools/box/vendor: tools/box/composer.lock tools/box/composer.json
	@composer --working-dir tools/box install

PHONY: clean
clean:
	@rm -rvf ../bin/ssh-verify tools/box/vendor

