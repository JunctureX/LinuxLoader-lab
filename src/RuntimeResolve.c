#include <elf.h>
#include <stdlib.h>
#include <stdio.h>

#include "Link.h"
#include "LoaderInternal.h"

Elf64_Addr __attribute__((visibility ("hidden"))) //this makes trampoline to call it w/o plt
runtimeResolve(LinkMap *lib, Elf64_Word reloc_entry)
{
    printf("Resolving address for entry %u\n", reloc_entry);
    /* Your code here */
    Elf64_Sym *sym=(typeof(sym))lib->dynInfo[DT_SYMTAB]->d_un.d_ptr;
    Elf64_Rela *frel=(typeof(frel))lib->dynInfo[DT_JMPREL]->d_un.d_ptr;
    frel += reloc_entry;
    int relsz=lib->dynInfo[DT_PLTRELSZ]->d_un.d_val/sizeof(Elf64_Rela);
    char *str=(char*)lib->dynInfo[DT_STRTAB]->d_un.d_ptr;
    Elf64_Addr *got=(void*)(lib->addr+frel->r_offset);
    for(int i=0;i<lib->depcnt;++i){
        uint64_t tmp = (uint64_t)symbolLookup(lib->dep[i],str+sym[frel->r_info>>32].st_name);
        if(tmp!=0){
            *got = tmp + frel->r_addend;
  //          fprintf(stderr,"found!\n");
            break;
        }
    }
  //  fprintf(stderr,"Done %p\n",*got);
    return *got;
}