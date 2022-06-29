#include <math.h>
#include <unistd.h>

#define MAX_SIZE pow(10,8)
#define BAD_SBRK ((void*)(-1))

bool validate(size_t size){
    return size != 0 && size <= MAX_SIZE;
}

void* smalloc(size_t size){
    void* ppd;
    if (!validate(size) || (ppd = sbrk(size)) == BAD_SBRK)
        return NULL;
    return ppd;
}