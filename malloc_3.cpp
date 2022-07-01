#include <math.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

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
void print_md(MD);
#define Ceil8(x) ((x%8==0 ? x : x+8-x%8))
#define MD_SIZE (sizeof(struct MallocMetaData_t))
#define MD_8SIZE (Ceil8(MD_SIZE))
#define MMAP_SIZE (128 * 1024)
#define SPLIT_SIZE (128 + MD_8SIZE)

//*********START - GENERAL UTILS************//
bool validate_size(size_t size){
    return size != 0 && size <= MAX_SIZE;
}

void* md2d(MD md){
    return (void*) (((char*)md)+MD_8SIZE);
}

MD d2md(void* d){
    return (MD)((char*)d - MD_8SIZE);
}


//*********END - GENERAL UTILS************//

//*********START - LIST************//
struct MallocMetaData_t head_t = {&head_t, &head_t, false,true, 0, &head_t};
struct MallocMetaData_t map_head_t = {&map_head_t, &map_head_t, false,false, 0, NULL};
MD head = (MD) &head_t;
MD map_head = (MD) &map_head_t;

MD ncc1701d = NULL;

void print_heap(){
	printf("printing heap:\n\n");
	for(MD curr = head->next; curr != head; curr=curr->next){
		print_md(curr);
	}
	printf("\n");
}
bool is_wild(MD md){
    return md == ncc1701d;
}

bool is_empty(MD l){
    return l->next == l;
}

void _insert_before(MD new_md, MD pos){
    printf("pos = %p\n", (void*) pos);
	new_md->prev = pos->prev;
    printf("set prev - %p\n",(void*)pos->prev);
    pos->prev->next = new_md;
    printf("set next\n");


    pos->prev = new_md;
    printf("set prev\n");
    new_md->next = pos;
    printf("set next\n");
}

void _remove(MD md){
	printf("in _remove\n");
	//print_md(md);
	printf("removeing %p\tprev=%p\n", (void*) md, (void*)md->prev);
    md->prev->next = md->next;
    printf("unchained prev\n");
    md->next->prev = md->prev; 
    printf("unchained next\n");
}

void push_back(MD l, MD md){
    _insert_before(md, l);
}



typedef bool (*BlockFilter) (MD, void*);

MD get_first(MD l, BlockFilter filter, void* args){
    MD curr = l->next;
    for(;curr != l && !filter(curr, args); curr=curr->next);
    return (curr == l ? NULL: curr);
}

struct lex_key{
    size_t size;
    void* addr;
};

typedef struct lex_key* LK;

bool size_x_addr_lex(MD md, void* void_key){
    LK key = (LK) void_key;
    return md->size > key->size || (md->size == key->size && md > key->addr);
}

void insert(MD md){
    lex_key md_key = {md->size, (void*) md};
    printf("assigned key\n");
    MD first_greater = get_first(head, size_x_addr_lex, &md_key);
    printf("got greater - %p\n", (void*) first_greater);
    (first_greater!=NULL ? _insert_before(md, first_greater) : push_back(head, md));
}

//*********END - LIST************//


//*********START - ALLOC UTILS************//

void* enterprise_expansion(size_t size){
    if(sbrk(size - (ncc1701d->size)) == BAD_ALLOC)
        return NULL;
    ncc1701d->size = size;
    return ncc1701d;
}
void* new_map(size_t size){
	printf("mapping - %lu\n", size);
	void* p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	printf("mapped - %p\n", p);
	return p;
}

//for sure - size%8==0
void* _new_assign(size_t size){
    size_t full_size = size + MD_8SIZE;  //8 multiplicant
    bool is_heap = full_size < MMAP_SIZE;
    //wilderness expantion
    if(is_heap && ncc1701d && ncc1701d->is_free)
        return enterprise_expansion(size);
    printf("is heap = %d\n", is_heap);
    MD new_md = (MD)(is_heap ? sbrk(full_size) : new_map(full_size));
    
    if (new_md == BAD_ALLOC)
        return NULL;
    
    printf("good alloc - %p\n", (void*) new_md);
    new_md->size = size;
    new_md->is_free = false;
    new_md->is_heap = is_heap;

    if(new_md->is_heap){
        new_md->adjacent_prev = ncc1701d;
        ncc1701d = new_md;  //setting new frontier
	printf("inserting\n");
        insert(new_md);
	printf("inserted\n");
    }
    else{
        push_back(map_head, new_md);
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
    
    if(is_wild(old_md))
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
void print_md(MD md){
	printf("addr=%p\tprev=%p\tnext=%p\tfree=%d\theap=%d\tsize=%lu\tap=%p\n", (void*)md, (void*)md->prev, (void*)md->next, md->is_free, md->is_heap, md->size, (void*)md->adjacent_prev);
}
void* smalloc(size_t size){
	print_heap();
    printf("smalloc start %lu\n", size);
	size = Ceil8(size);
    if(!validate_size(size))
        return NULL;
    MD first_fit = get_first(head, free_n_fit, &size);
    
    // notice that for size > MMAP first_fit must return as NULL
    //return first_fit!=NULL ? _re_assign(first_fit, size) : _new_assign(size);
    void* p =  (first_fit!=NULL ? _re_assign(first_fit, size) : _new_assign(size));
    printf("done smalloc\n");
    print_md(d2md(p));
    return p;
}

void* scalloc(size_t num, size_t size){
    void* allocated_block = smalloc(num*size);
    if(allocated_block)
        memset(allocated_block, 0, num*size);

    return allocated_block;
}

void free_map(MD md){
	printf("freeing map - %p\n", (void*) md);
    _remove(md);
    if(munmap((void*) md, md->size + MD_8SIZE) == -1)
        printf("handle bad munmap\n");
    printf("freed map - %p\n", (void*) md);
}

MD get_next_adjacent(MD md){
    return is_wild(md) ? NULL : (MD)((char*)md + MD_8SIZE + md->size);
}

MD get_prev_adjacent(MD md){
    return md->adjacent_prev;
}

MD merge(MD left, MD right){
	printf("start merge : %p to %p\n", (void*)right, (void*) left);
    _remove(right);
    left->size += right->size + MD_8SIZE;
    
    if(is_wild(right))
        ncc1701d = left;
    else{
	    get_next_adjacent(right)->adjacent_prev = right->adjacent_prev;
    }
    
	printf("done merge : %p to %p\n", (void*)right, (void*) left);
    return left;
}

void free_heap(MD md){
    md->is_free = true;
    MD next = get_next_adjacent(md);
    printf("got next = %p\n", (void*) next);
    if(next != NULL  && next->is_free){
	    printf("in merge next\n");
	    print_md(next);
        md = merge(md, next);
    }
    
    MD prev = get_prev_adjacent(md);
    if(prev != NULL && prev->is_free){
	    printf("in merge prev\n");
        md = merge(prev, md);
    } 
    _remove(md);
    insert(md);
}

void sfree(void* p){
	printf("start free - %p\tis_heap = %d\n", p, d2md(p)->is_heap);
	print_heap();
    if(p){
        MD p_md = d2md(p);
        p_md->is_heap ? free_heap(p_md) : free_map(p_md);
    }
	printf("done free - %p\n", p);
	print_heap();
}

void* srealloc(void* oldp, size_t size){
    size = Ceil8(size);
    size_t full_size = size + MD_8SIZE;
    MD oldp_md, new_md;
    if(oldp && (oldp_md=d2md(oldp))->size >= size)
        return oldp;
    
    size_t copy_size = oldp_md->size + MD_8SIZE;
    
    if(!(oldp_md->is_heap)){
        new_md = (MD) new_map(full_size);
        if(new_md == NULL)
            return NULL;
        memmove(new_md, oldp_md, copy_size);
        new_md->size = size;
        free_map(oldp_md);
        return new_md;
    }

    MD prev = get_prev_adjacent(oldp_md);
    if(prev && prev->is_free && prev->size + oldp_md->size +MD_8SIZE >= size){
        new_md = merge(prev, oldp_md);
        memmove(new_md, oldp_md, copy_size);
        
        if(new_md->size - size > SPLIT_SIZE)
            split_block(new_md, size);
        return new_md;
    }

    else if(prev && prev->is_free && is_wild(oldp_md)){
        size_t alloc_size = size - prev->size;
        bool is_free = oldp_md->is_free;
        oldp_md->is_free = true;
       	new_md = d2md(_new_assign(alloc_size));
        oldp_md->is_free = is_free;
        new_md = merge(prev, new_md);
        memmove(new_md, oldp_md, copy_size);

        if(new_md->size - size > SPLIT_SIZE)
            split_block(new_md, size);
        
        return new_md;
    }

    else if(is_wild(oldp_md)){
        bool is_free = oldp_md->is_free;
        oldp_md->is_free = true;
        new_md = d2md(_new_assign(size));
        oldp_md->is_free = is_free;
        return oldp_md;
    }

    MD next = get_next_adjacent(oldp_md);
    if(next && next->is_free && next->size + oldp_md->size + MD_8SIZE >= size){
        new_md = merge(oldp_md, next);
        
        if(new_md->size - size > SPLIT_SIZE)
            split_block(new_md, size);
            
        return new_md;
    }
    else if(prev && prev->is_free && next&&next->is_free&&prev->size + oldp_md->size + next->size +2*MD_8SIZE >= size){
        new_md = merge(prev, oldp_md);
        memmove(new_md, oldp_md, copy_size);
        new_md = merge(new_md, next);

        if(new_md->size - size > SPLIT_SIZE)
            split_block(new_md, size);

        return new_md;
    }

    else if(next && next->is_free && is_wild(next)){
        if(prev && prev->is_free){
            size_t alloc_size = size - (prev->size + 2*MD_8SIZE + oldp_md->size);
            _new_assign(alloc_size);
            new_md = merge(prev, oldp_md);
            memmove(new_md, oldp_md, copy_size);
            new_md = merge(new_md, next);
        }
        
        else{
            size_t alloc_size = size - (MD_8SIZE + oldp_md->size);
            _new_assign(alloc_size);
            new_md = merge(prev, oldp_md);   
        }

        if(new_md->size - size > SPLIT_SIZE)
            split_block(new_md, size);

        return new_md;
    }

    else{
        void* newp = smalloc(size);
        if(newp){
            memmove(newp, oldp, oldp_md->size);
            free_heap(oldp_md);
        }
        return newp;
    }

}
//*********END - REQUSTED FUNCTIONS************//

//*********START - STATS METHODS************//
typedef void (*StatsUpdater) (MD, void*);

void get_stats(MD l, void* stats, BlockFilter filter, void* filter_args, StatsUpdater updater){
    for(MD curr = l->next; curr != l; curr=curr->next)
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
    get_stats(head, &counter, is_free, NULL, count);
    return counter;
}

size_t _num_free_bytes(){
    size_t bytes_counter = 0;
    get_stats(head, &bytes_counter, is_free, NULL, bytes_count);
    return bytes_counter;
}

size_t _num_allocated_blocks(){
    size_t counter=0;
    get_stats(head, &counter, tautology, NULL, count);
    printf("countr = %lu\n",counter);
    get_stats(map_head, &counter, tautology, NULL, count);
    return counter;
}

size_t _num_allocated_bytes(){
    size_t bytes_counter=0;
    get_stats(head, &bytes_counter, tautology, NULL, bytes_count);
    get_stats(map_head, &bytes_counter, tautology, NULL, bytes_count);
    return bytes_counter;
}

size_t _num_meta_data_bytes(){
    return _num_allocated_blocks() * MD_8SIZE;
}

size_t _size_meta_data(){
    return MD_8SIZE;
}

//*********END - STATS METHODS************//
