cmake_minimum_required(VERSION 3.16)
project(CaCertsUpdater LANGUAGES OBJC)

find_package(MavericksShipyard REQUIRED)
include(Mavericks)
include(MavericksSparkle)

mavericks_resolve_version(CA_CERTS_VERSION)

mavericks_add_updater_app(
  PRODUCT ca-certs
  PRODUCT_NAME "Mavericks CA Certificates"
  ALLOW_GENERIC   # no bespoke artwork, and no third party's mark to borrow
  VERSION "${CA_CERTS_VERSION}"
  CONFIRM_TITLE "Mavericks CA Certificates updated"
  CONFIRM_BODY "CA Certificates for Mavericks was updated, and its roots were re-applied."
)
