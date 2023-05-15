#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <elf.h>
#include <unistd.h> //for getpagesize
#include <sys/mman.h>
#include <fcntl.h>

#include "Link.h"
#include "LoaderInternal.h"

#define ALIGN_DOWN(base, size) ((base) & -((__typeof__(base))(size)))
#define ALIGN_UP(base, size) ALIGN_DOWN((base) + (size)-1, (size))

static const char *sys_path[] = {
    "/usr/lib/x86_64-linux-gnu/",
    "/lib/x86_64-linux-gnu/",
    ""
};

static const char *fake_so[] = {
    "libc.so.6",
    "ld-linux.so.2",
    ""
};

static void setup_hash(LinkMap *l)
{
    uint32_t *hash;

    /* borrowed from dl-lookup.c:_dl_setup_hash */
    Elf32_Word *hash32 = (Elf32_Word *)l->dynInfo[DT_GNU_HASH]->d_un.d_ptr;
    l->l_nbuckets = *hash32++;
    Elf32_Word symbias = *hash32++;
    Elf32_Word bitmask_nwords = *hash32++;

    l->l_gnu_bitmask_idxbits = bitmask_nwords - 1;
    l->l_gnu_shift = *hash32++;

    l->l_gnu_bitmask = (Elf64_Addr *)hash32;
    hash32 += 64 / 32 * bitmask_nwords;

    l->l_gnu_buckets = hash32;
    hash32 += l->l_nbuckets;
    l->l_gnu_chain_zero = hash32 - symbias;
}

static void fill_info(LinkMap *lib)
{
    Elf64_Dyn *dyn = lib->dyn;
    Elf64_Dyn **dyn_info = lib->dynInfo;

    while (dyn->d_tag != DT_NULL)
    {
        /*
        if(dyn->d_tag == DT_RELAENT){
            fprintf(stderr,"RELAENT : %d\n",dyn->d_un.d_val);
        }
        if(dyn->d_tag == DT_RELASZ){
            fprintf(stderr,"RELASZ : %d\n",dyn->d_un.d_val);
        }
        if(dyn->d_tag == DT_RELACOUNT_){
            fprintf(stderr,"RELACOUNT : %d\n",dyn->d_un.d_val);
        }
        */
        if ((Elf64_Xword)dyn->d_tag < DT_NUM)
            dyn_info[dyn->d_tag] = dyn;
        else if ((Elf64_Xword)dyn->d_tag == DT_RELACOUNT_)
            dyn_info[DT_RELACOUNT] = dyn;
        else if ((Elf64_Xword)dyn->d_tag == DT_GNU_HASH_)
            dyn_info[DT_GNU_HASH] = dyn;
        ++dyn;
    }
    #define rebase(tag)                             \
        do                                          \
        {                                           \
            if (dyn_info[tag])                          \
                dyn_info[tag]->d_un.d_ptr += lib->addr; \
        } while (0)
    rebase(DT_SYMTAB);
    rebase(DT_STRTAB);
    rebase(DT_RELA);
    rebase(DT_JMPREL);
    rebase(DT_GNU_HASH); //DT_GNU_HASH
    rebase(DT_PLTGOT);
    rebase(DT_INIT);
    rebase(DT_INIT_ARRAY);
}

void *MapLibrary(const char *libpath)
{
    /*
     * hint:p_memsz+mov,pagesize),prot,
                    MAP_PRIVATE,fd,ALIGN_DOWN(cur->p_offset,pagesize))
                    +mov;
                break;
            }symname, name))
                    {    
                        Elf64_Sym *s = &symtab[symidx];
                        // return the real address of found symbol
                        return (void *)(s->st_v
     * lib = malloc(sizeof(LinkMap));
     * 
     * foreach segment:
     * mmap(start_addr, segment_length, segment_prot, MAP_FILE | ..., library_fd, 
     *      segment_offset);
     * 
     * lib -> addr = ...;
     * lib -> dyn = ...;
     * 
     * fill_info(lib);
     * setup_hash(lib);
     * 
     * return lib;
    */
   
    /* Your code here */
    LinkMap *lib=malloc(sizeof(LinkMap));
    lib->name=libpath;
    lib->dyn=NULL;
    if(strcmp(libpath,"libc.so.6")==0){
        lib->fake = 1;
        lib->fakeHandle = (void*)-1;
        return lib;
    }
    char truepath[100];
    sprintf(truepath,libpath[0]=='.'?"%s":"./test_lib/%s",libpath);
    int fd=open(truepath,O_RDONLY);
    if(fd==-1){
        fprintf(stderr,"%s not found!\n",libpath);
        abort();
    }
    Elf64_Ehdr ehd;
    pread(fd,&ehd,sizeof(Elf64_Ehdr),0);
    //Elf64_Phdr *segments=(Elf64_Phdr*)((unsigned char*)&ehd+ehd.e_phoff);
    //fprintf(stderr,"handle : %d\n",fd);
    //fprintf(stderr,"atbeginning : e_phnum : %d\n",ehd.e_phnum);
    const int pagesize=getpagesize();
    int mxsz=0;
    Elf64_Addr fir=0;
    for(int i=0;i<ehd.e_phnum;++i){
        Elf64_Phdr *cur=malloc(sizeof(Elf64_Phdr));
        pread(fd,cur,sizeof(Elf64_Phdr),ehd.e_phoff+i*sizeof(Elf64_Phdr));
        if(i==0)fir=cur->p_vaddr;
        if(cur->p_type==PT_LOAD||cur->p_type==PT_DYNAMIC){
            size_t nx=ALIGN_UP(cur->p_vaddr-fir+cur->p_memsz-1,pagesize);
            if(mxsz<nx)mxsz=nx;
        }
        free(cur);
    }
    if(fir!=0){
        fprintf(stderr,"fir not 0\n");
        abort();
    }
    void *address=NULL;
    for(int i=0,first=1;i<ehd.e_phnum;++i){
        Elf64_Phdr *cur=malloc(sizeof(Elf64_Phdr));
        pread(fd,cur,sizeof(Elf64_Phdr),ehd.e_phoff+i*sizeof(Elf64_Phdr));
        int prot=0;
        prot|=(cur->p_flags&PF_R)?PROT_READ:0;
        prot|=(cur->p_flags&PF_X)?PROT_EXEC:0;
        prot|=(cur->p_flags&PF_W)?PROT_WRITE:0;
        int mov=cur->p_offset-ALIGN_DOWN(cur->p_offset,pagesize);
        if(cur->p_type==PT_LOAD){
            if(first){
                address=mmap(NULL,mxsz,prot,
                    MAP_PRIVATE,fd,ALIGN_DOWN(cur->p_offset,pagesize));
                lib->addr=(uint64_t)address+mov;
                first=0;
            }else{
                mmap(address+cur->p_vaddr-fir-mov,
                    ALIGN_UP(cur->p_memsz+mov,pagesize),prot,
                    MAP_PRIVATE|MAP_FIXED,fd,ALIGN_DOWN(cur->p_offset,pagesize));
            }
        }
        free(cur);
    }

//    fprintf(stderr,"trying to find %x\n",PT_DYNAMIC);
//    fprintf(stderr,"currently at %s\n",libpath);
//    fprintf(stderr,"segmentcount : %d\n", ehd.e_phnum);
//    int found=0;
    for(int i=0;i<ehd.e_phnum;++i){
        Elf64_Phdr *cur=malloc(sizeof(Elf64_Phdr));
        pread(fd,cur,sizeof(Elf64_Phdr),ehd.e_phoff+i*sizeof(Elf64_Phdr));
        //fprintf(stderr,"%d read a segment of type : %u address : %lu\n",i,(uint32_t)cur->p_type, (uint64_t)cur->p_vaddr);
        if(cur->p_type==PT_DYNAMIC){
            lib->dyn=address+cur->p_vaddr-fir;
//            found = 1;
//            fprintf(stderr,"here we go!\n");
//            fprintf(stderr,"current found1 : %d\n", found);
            break;
        }
    }
//    fprintf(stderr,"current found2 : %d\n", found);
//    if(found==0){
//        fprintf(stderr,"PT_DYNAMIC not found!\n");
//        abort();
//    }
//    fprintf(stderr,"\n");
//    if(lib->dyn==NULL)
//        return lib;
    fill_info(lib);
    setup_hash(lib);
    
    Elf64_Dyn *dyn=lib->dyn;
    char *str = (char*)lib->dynInfo[DT_STRTAB]->d_un.d_ptr;
/*
    char outp[100];
    sprintf(outp,"%s.txt",libpath);
    FILE *fout = fopen(outp,"w");
    fprintf(fout,"finish mapping :%s\n", lib->name); 
    
    while(dyn->d_tag!=DT_NULL){
        if(dyn->d_tag == DT_NEEDED){
            fprintf(fout,"findstr : %d\n",dyn->d_un.d_val);
            fprintf(fout,"dep : %s\n",str+dyn->d_un.d_val);
        }
        ++dyn;
    }
    fclose(fout);
*/
    lib->depcnt = 0;
    dyn = lib->dyn;
    while(dyn->d_tag!=DT_NULL){
        if(dyn->d_tag == DT_NEEDED){
            ++lib->depcnt;
        }
        ++dyn;
    }
    if(lib->depcnt > 0)
        lib->dep=malloc(sizeof(LinkMap*)*(lib->depcnt+10));
    int cur=0;
    dyn = lib->dyn;
    while(dyn->d_tag!=DT_NULL){
        if(dyn->d_tag==DT_NEEDED){
            lib->dep[cur++] = MapLibrary(str+dyn->d_un.d_val);
    //        fprintf(fout,"go : %s\n",str+dyn->d_un.d_val);
        }
        ++dyn;
    }
    return lib;
}
