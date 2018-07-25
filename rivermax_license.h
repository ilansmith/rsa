#ifndef _RIVERMAX_LICENSE_
#define _RIVERMAX_LICENSE_

#if defined(__linux__)
#define RIVERMAX_LICENSE_PATH_DEFAULT "/opt/mellanox/rivermax/rivermax.lic"
#else
#define RIVERMAX_LICENSE_PATH_DEFAULT "c:\\Program Files\\Mellanox\\Rivermax\\lib\\rivermax.lic"
#endif

#define RIVERMAX_LICENSE_PATH_ENV "RIVERMAX_LICENSE_PATH"
#define RIVERMAX_KEY_PATH_ENV "RIVERMAX_KEY_PATH"

namespace rivermax {

int license_extract(std::string &key_path, std::string &license);

}

#endif

