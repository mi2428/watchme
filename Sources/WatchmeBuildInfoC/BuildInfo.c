#include "WatchmeBuildInfoC.h"

#ifndef WATCHME_PACKAGE_NAME
#define WATCHME_PACKAGE_NAME "watchme"
#endif

#ifndef WATCHME_PACKAGE_VERSION
#define WATCHME_PACKAGE_VERSION "0.1.0"
#endif

#ifndef WATCHME_GIT_DESCRIBE
#define WATCHME_GIT_DESCRIBE "unknown"
#endif

#ifndef WATCHME_GIT_COMMIT
#define WATCHME_GIT_COMMIT "unknown"
#endif

#ifndef WATCHME_GIT_COMMIT_DATE
#define WATCHME_GIT_COMMIT_DATE "unknown"
#endif

#ifndef WATCHME_BUILD_DATE
#define WATCHME_BUILD_DATE "unknown"
#endif

#ifndef WATCHME_BUILD_HOST
#define WATCHME_BUILD_HOST "unknown"
#endif

#ifndef WATCHME_BUILD_TARGET
#define WATCHME_BUILD_TARGET "unknown"
#endif

#ifndef WATCHME_BUILD_PROFILE
#define WATCHME_BUILD_PROFILE "debug"
#endif

const char *watchme_package_name(void) {
    return WATCHME_PACKAGE_NAME;
}

const char *watchme_package_version(void) {
    return WATCHME_PACKAGE_VERSION;
}

const char *watchme_git_describe(void) {
    return WATCHME_GIT_DESCRIBE;
}

const char *watchme_git_commit(void) {
    return WATCHME_GIT_COMMIT;
}

const char *watchme_git_commit_date(void) {
    return WATCHME_GIT_COMMIT_DATE;
}

const char *watchme_build_date(void) {
    return WATCHME_BUILD_DATE;
}

const char *watchme_build_host(void) {
    return WATCHME_BUILD_HOST;
}

const char *watchme_build_target(void) {
    return WATCHME_BUILD_TARGET;
}

const char *watchme_build_profile(void) {
    return WATCHME_BUILD_PROFILE;
}
