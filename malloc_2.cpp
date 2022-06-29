#include <math.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#define MAX_SIZE pow(10, 8)
#define BAD_SBRK ((void*)(-1))

struct MallocMetaData_t;
typedef struct MallocMetaData_t* MD;

struct MallocMetaData_t{
    MD prev;
    MD next;
    bool is_free;
    size_t size;
};

#define MD_SIZE (sizeof(struct MallocMetaData_t))

//*********START - GENERAL UTILS************//
bool validate_size(size_t size){
    return size != 0 && size <= MAX_SIZE;
}

void* md2d(MD md){
    return (void*) (md+MD_SIZE);
}

MD d2md(void* d){
    return (MD)d - MD_SIZE;
}


//*********END - GENERAL UTILS************//

//*********START - LIST************//

struct MallocMetaData_t head_t = {&head_t, &head_t, false, 0};
//head_t.next = &head_t;
//head_t.prev = &head_t;
MD head = (MD) &head_t;
//head->prev = head;
//head->next = head;

bool is_empty(){
    return head->next == head;
}

void _insert_before(MD new_md, MD pos){
    new_md->prev = pos->prev;
    pos->prev->next = new_md;

    pos->prev = new_md;
    new_md->next = pos;
}

void push_back(MD md){
    _insert_before(md, head);
}

void insert(MD md){
    if(is_empty())
        push_back(md);
}

typedef bool (*BlockFilter) (MD, void*);

MD get_first(BlockFilter filter, void* args){
    MD curr = head->next;
    for(;curr != head && !filter(curr, args); curr=curr->next);
    return (curr == head ? NULL: curr);
}

//*********END - LIST************//


//*********START - ALLOC UTILS************//

//calls sbrk for new allocation (including its metadata), and add its metadata to end of list
//similar code to smalloc from malloc_1.cpp
void* _new_assign(size_t size){
    size_t full_size = size + MD_SIZE;
    void* ppd = sbrk(full_size);
    if (ppd == BAD_SBRK)
        return NULL;
    
    MD new_md = (MD) ppd;
    new_md->size = size;
    new_md->is_free = false;
    push_back(new_md);

    return md2d(new_md);    
}

void* _re_assign(MD old_md){
    //old_md->size = size;  (md->size should not be changed - mentioned in WHW4)
    old_md->is_free = false;
    return md2d(old_md);
}

bool free_n_fit(MD md, void* size_ptr){
    return md->is_free && md->size >= *((size_t*)size_ptr);
}

//*********END - ALLOC UTILS************//


//*********START - REQUSTED FUNCTIONS************//

void* smalloc(size_t size){
    if(!validate_size(size))
        return NULL;

    MD first_fit = get_first(free_n_fit, &size);
    return (first_fit ? _re_assign(first_fit) : _new_assign(size));
}

void* scalloc(size_t num, size_t size){
    void* allocated_block = smalloc(num*size);
    if(allocated_block)
        memset(allocated_block, 0, num*size);

    return allocated_block;
}

void sfree(void* p){
    MD p_md;
    if(p && !(p_md = d2md(p))->is_free)
        p_md->is_free = true;
}

void* srealloc(void* oldp, size_t size){
    MD oldp_md;
    if(oldp && (oldp_md=d2md(oldp))->size >= size)
        return oldp;

    void* newp = smalloc(size);
    if(oldp && newp){
        memmove(newp, oldp, oldp_md->size);
        sfree(oldp);
    }
    return newp;
}
//*********END - REQUSTED FUNCTIONS************//

//*********START - STATS METHODS************//
typedef void (*StatsUpdater) (MD, void*);

void get_stats(void* stats, BlockFilter filter, void* filter_args, StatsUpdater updater){
    for(MD curr = head->next; curr != head; curr=curr->next)
        if(filter(curr, filter_args))
            updater(curr, stats);
}

//******FILTERS*****//
bool is_free(MD md, void* args){
    return md->is_free;
}

bool tautology(MD md, void* args){
    return true;
}


//******UPDATERS*****//
void count(MD md, void* stats){
    *(size_t*)stats += 1;
}
void bytes_count(MD md, void* stats){
    *(size_t*)stats += md->size;
}


//******REQUSTED STATS METHODS*******
size_t _num_free_blocks(){
    size_t counter = 0;
    get_stats(&counter, is_free, NULL, count);
    return counter;
}

size_t _num_free_bytes(){
    size_t bytes_counter = 0;
    get_stats(&bytes_counter, is_free, NULL, bytes_count);
    return bytes_counter;
}

size_t _num_allocated_blocks(){
    size_t counter=0;
    get_stats(&counter, tautology, NULL, count);
    return counter;
}

size_t _num_allocated_bytes(){
    size_t bytes_counter=0;
    get_stats(&bytes_counter, tautology, NULL, bytes_count);
    return bytes_counter;
}

size_t _num_meta_data_bytes(){
    return _num_allocated_blocks() * MD_SIZE;
}

size_t _size_meta_data(){
    return MD_SIZE;
}

//*********END - STATS METHODS************//
