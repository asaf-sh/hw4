#include <math.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include <sys/mman.h>

#define MAX_SIZE pow(10, 8)
#define BAD_ALLOC ((void*)(-1))

struct MallocMetaData_t;
typedef struct MallocMetaData_t* MD;

struct MallocMetaData_t{
    MD prev;
    MD next;
    bool is_free;
    bool is_heap;
    size_t size;
    MD adjacent_prev;
};

#define Ceil8(x) ((x%8 ? x+8-%8 : x))
#define MD_SIZE (sizeof(struct MallocMetaData_t))
#define MD_8SIZE (Ceil8(MD_SIZE))
#define MMAP_SIZE (128 * 1024)
#define SPLIT_SIZE (128 + MD_8SIZE)

//*********START - GENERAL UTILS************//
bool validate_size(size_t size){
    return size != 0 && size <= MAX_SIZE;
}

void* md2d(MD md){
    return (void*) (md+MD_8SIZE);
}

MD d2md(void* d){
    return (MD)d - MD_8SIZE;
}


//*********END - GENERAL UTILS************//

//*********START - LIST************//

struct MallocMetaData_t head_t = {&head_t, &head_t, false, 0};
MD head = (MD) &head_t;

MD ncc1701d = NULL;
MD elizabeth2 = NULL;


bool is_empty(){
    return head->next == head;
}

void _insert_before(MD new_md, MD pos){
    new_md->prev = pos->prev;
    pos->prev->next = new_md;

    pos->prev = new_md;
    new_md->next = pos;
}

void _remove(MD md){
    md->prev->next = md->next;
    md->next->prev = md->prev;
}

void push_back(MD md){
    _insert_before(md, head);
}



typedef bool (*BlockFilter) (MD, void*);

MD get_first(BlockFilter filter, void* args){
    MD curr = head->next;
    for(;curr != head && !filter(curr, args); curr=curr->next);
    return (curr == head ? NULL: curr);
}

struct lex_key{
    size_t size;
    void* addr;
}
typedef struct lex_key* LK;

bool size_x_addr_lex(MD md, void* void_key){
    LK key = (LK) void_key;
    return md->size > key->size || (md->size == key->size && md > key->addr);
}

void insert(MD md){
    lex_key md_key = {md->size, md};
    MD first_greater = get_first(size_x_addr_lex, &md_key);
    first_greater ? _insert_before(md, first_greater) : push_back(md);
}

//*********END - LIST************//


//*********START - ALLOC UTILS************//

//for sure - size%8==0
void* _new_assign(size_t size){
    size_t full_size = size + MD_8SIZE;  //8 multiplicant

    //wilderness expantion
    if(full_size < MMAP_SIZE && ncc1701d && ncc1701d->is_free){
        if(sbark(size - ncc1701d->size) == BAD_ALLOC)
            return NULL;
        ncc1701d->size = size;
        return ncc1701d;
    }

    MD new_md = (full_size < MMAP_SIZE ? sbrk(full_size - (ncc1701d->is_free * ncc1701d->size)) : \
                    mmap(NULL, full_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    
    if (new_md == BAD_ALLOC)
        return NULL;
    
    new_md->size = size;
    new_md->is_free = false;
    new_md->is_heap = (full_size < MMAP_SIZE);

    if(new_md->is_heap){
        new_md->adjacent_prev = ncc1701d;
        ncc1701d = new_md;  //setting new frontier
        insert(new_md);
    }
    
    return md2d(new_md);    
}

void split_block(MD old_md, size_t offset){
    MD new_md = (old_md + MD_8SIZE) + offset;
    new_md->is_free = true;
    new_md->size = old_md->size - (offset + MD_8SIZE);
    new_md->is_heap = true;
    new_md->adjacent_prev = old_md;
    insert(new_md);
    
    old_md->size = offset;
    
    if(old_md == ncc1701d)
        ncc1701d = new_md;
}

void* _re_assign(MD old_md, size_t size){
    //old_md->size = size;  (md->size should not be changed - mentioned in WHW4)
    old_md->is_free = false;
    if(old_md->size - size > SPLIT_SIZE)
        split_block(old_md, size);

    return md2d(old_md);
}

bool free_n_fit(MD md, void* size_ptr){
    return md->is_free && md->size >= *((size_t*)size_ptr);
}

//*********END - ALLOC UTILS************//


//*********START - REQUSTED FUNCTIONS************//

void* smalloc(size_t size){
    size = Ceil8(size);
    if(!validate_size(size))
        return NULL;
    MD first_fit = get_first(free_n_fit, &size);
    
    // notice that for size > MMAP first_fit must return as NULL
    return first_fit ? _re_assign(first_fit, size) : _new_assign(size);
}

void* scalloc(size_t num, size_t size){
    void* allocated_block = smalloc(num*size);
    if(allocated_block)
        memset(allocated_block, 0, num*size);

    return allocated_block;
}

void free_map(MD md){
    if(munmap(p, p_md->size + MD_8SIZE) == -1)
        printf("handle bad munmap");
}

MD get_next_adjacent(MD md){
    return md == ncc1701d ? NULL : md + MD_8SIZE + md->size;
}

MD get_prev_adjacent(MD md){
    return md->adjacent_prev;
}

MD merge(MD left, MD right){
    _remove(right);
    left->size += right->size + MD_8SIZE;
    
    if(right == ncc1701d)
        ncc1701d = left;
    
    return left;
}

void free_heap(MD md){
    md->is_free = true;
    MD next = get_next_adjacent(md);
    if(next && next->is_free)
        md = merge(md, next);
    
    MD prev = get_prev_adjacent(md);
    if(prev && prev->is_free)
        md = merge(prev, md);
    
    _remove(md);
    insert(md);
}

void sfree(void* p){
    if(p){
        MD p_md = (MD)p;
        (MD)p->is_heap ? free_heap(p_md) : free_map(p_md);
    }
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
