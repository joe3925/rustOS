#ifndef RUSTOS_UNISTD_H
#define RUSTOS_UNISTD_H

#define _PC_PATH_MAX 4

long pathconf(const char* path, int name);
char* realpath(const char* restrict path, char* restrict resolved_path);

#endif
