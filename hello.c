#include <stdio.h>

int main() {
  printf("Hello world%s\n");


}

int do_something() {

  printf("Hello world from do_something%s\n");

  int i = 0;

  for (i; i< 5; i++) {
    printf("i: %d\n", i);
  }
}
