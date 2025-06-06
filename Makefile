include $(TOPDIR)/rules.mk

PKG_NAME:=nft-dns
PKG_VERSION:=1.0
PKG_RELEASE:=1

SOURCE_DIR:=./src
PKG_BUILD_DIR:=$(BUILD_DIR)/nft-dns-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/nft-dns
  CATEGORY:=base
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