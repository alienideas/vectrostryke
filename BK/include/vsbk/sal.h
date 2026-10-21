#ifndef VSBK_SAL_H
#define VSBK_SAL_H

#include <stddef.h>
#include <stdio.h>

typedef struct vsbk_storage vsbk_storage_t;

vsbk_storage_t *vsbk_storage_open_local(const char *root);
void            vsbk_storage_close(vsbk_storage_t *s);
int vsbk_storage_put_file(vsbk_storage_t *s, const char *key, FILE *in, char *sha_out);
int vsbk_storage_put_mem(vsbk_storage_t *s, const char *key, const void *data, size_t len);
int vsbk_storage_exists(vsbk_storage_t *s, const char *key);
int vsbk_storage_delete(vsbk_storage_t *s, const char *key);

#endif /* VSBK_SAL_H */
