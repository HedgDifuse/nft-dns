include $(TOPDIR)/rules.mk

PKG_NAME:=nft-dns
PKG_VERSION:=1.0
PKG_RELEASE:=1
PKG_SOURCE_URL:=https://github.com/hedgdifuse/nft-dns.git
PKG_SOURCE_BRANCH:=github/master
PKG_SOURCE_PROTO:=git
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.xz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION).$(PKG_RELEASE)
PKG_SOURCE_VERSION:=1ce1a5374363417a800c151b6e6c57a1416c867e
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_SOURCE_SUBDIR)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/nft-dns
  SECTION:=network
  CATEGORY:=Utilities
  TITLE:=Simple local dns-forwarder for intercept dns responses
  DEPENDS:=+libnftnl +libmnl
endef

define Package/nft-dns/description
  Working as UDP/TCP local dns server, it's forwards all request to upstream dns (param --dns)
  When response is got filter it by domains list (must be located at /tmp/nft-dns.d/domains.lst)
  Domain list supports wildcard symbol before domain notation (*example.com, *.example.com, .example.com) for including subdomains
endef


define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef


define Package/nft-dns/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nft-dns $(1)/bin/
endef


$(eval $(call BuildPackage,$(PKG_NAME)))