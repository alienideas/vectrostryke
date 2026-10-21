#include "vsbk/sal.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  const char *root = "./data/test_sal_store";
  vsbk_mkdir_p(root);
  vsbk_storage_t *s = vsbk_storage_open_local(root);
  assert(s != NULL);

  const char *payload = "hello-vsbk-c";
  assert(vsbk_storage_put_mem(s, "a/b.txt", payload, strlen(payload)) == 0);
  assert(vsbk_storage_exists(s, "a/b.txt") == 1);
  assert(vsbk_storage_exists(s, "nope") == 0);

  vsbk_storage_close(s);
  printf("test_sal OK\n");
  return 0;
}
