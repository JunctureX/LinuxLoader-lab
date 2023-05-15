#include <stdlib.h>
#include <stdio.h>
#include <elf.h>
#include <stdint.h>
#include <string.h>

#include "Link.h"
#include "LoaderInternal.h"

void InitLibrary(LinkMap *l)
{
    /* Your code here */
//    fprintf(stderr,"InitLibrary : %s\n", l->name);
    Elf64_Dyn **dynInfo=l->dynInfo;
    Elf64_Rela *rela=NULL;
    int relacount=0;
    void (*init)()=NULL;
    void (**initarr)()=NULL;
    int initarrsz=0;
    char *str=NULL;
    Elf64_Sym *sym = NULL;
    if(dynInfo[DT_RELA])
        rela=(Elf64_Rela*)dynInfo[DT_RELA]->d_un.d_ptr;
    if(dynInfo[DT_RELACOUNT])
        relacount=dynInfo[DT_RELACOUNT]->d_un.d_val;
    if(dynInfo[DT_INIT])
        init=(typeof(init))dynInfo[DT_INIT]->d_un.d_ptr;
    if(dynInfo[DT_INIT_ARRAY])
        initarr=(typeof(initarr))dynInfo[DT_INIT_ARRAY]->d_un.d_ptr;
    if(dynInfo[DT_INIT_ARRAYSZ])
        initarrsz=dynInfo[DT_INIT_ARRAYSZ]->d_un.d_val/sizeof(void*);
    for(int i=0;i<relacount;++i,++rela){
        *(uint64_t*)(l->addr+rela->r_offset)=l->addr+rela->r_addend;
    }
//    fprintf(stderr,"hbxql\n");
    int nx = 0;
    if(dynInfo[DT_RELASZ]&&dynInfo[DT_RELAENT])
        nx = dynInfo[DT_RELASZ]->d_un.d_val/dynInfo[DT_RELAENT]->d_un.d_val - relacount;
    if(dynInfo[DT_STRTAB])
        str = (char*)dynInfo[DT_STRTAB]->d_un.d_ptr;
    if(dynInfo[DT_SYMTAB])
        sym = (typeof(sym))dynInfo[DT_SYMTAB]->d_un.d_ptr;
    for(int i = 0; i < nx; ++i, ++rela){
        if(ELF64_ST_BIND(sym[ELF64_R_SYM(rela->r_info)].st_info)==STB_WEAK){
            continue;
        }
        void * ptr = NULL;
        for(int j = 0; j < l->depcnt; ++j){
            ptr = symbolLookup(l->dep[j], str + sym[ELF64_R_SYM(rela->r_info)].st_name);
            if(ptr!=NULL)break;
        }
        if(ptr==NULL){
            ptr = symbolLookup(l, str + sym[ELF64_R_SYM(rela->r_info)].st_name);
        }
        *(uint64_t*)(l->addr+rela->r_offset)=(uint64_t)ptr+rela->r_addend;        
    }
//    fprintf(stderr,"RELOC FINISHED\n");
    init();
    for(int i=0;i<initarrsz;++i)
        initarr[i]();
}
