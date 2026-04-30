#ifndef WATCHME_BUILD_INFO_C_H
#define WATCHME_BUILD_INFO_C_H

const char *watchme_package_name(void);
const char *watchme_package_version(void);
const char *watchme_git_describe(void);
const char *watchme_git_commit(void);
const char *watchme_git_commit_date(void);
const char *watchme_build_date(void);
const char *watchme_build_host(void);
const char *watchme_build_target(void);
const char *watchme_build_profile(void);

#endif
