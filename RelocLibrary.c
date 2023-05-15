#include <dlfcn.h> //turn to dlsym for help at fake load object
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <elf.h>
#include <link.h>
#include <string.h>

#include "Link.h"

// glibc version to hash a symbol
static uint_fast32_t
dl_new_hash(const char *s)
{
    uint_fast32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s)
        h = h * 33 + c;
    return h & 0xffffffff;
}

// find symbol `name` inside the symbol table of `dep`
void *symbolLookup(LinkMap *dep, const char *name)
{
   // fprintf(stderr,"trying to look symbol %s in %s\n", name, dep->name);
    if(dep->fake)
    {
        if(dep->fakeHandle!=(void*)-1)
            return dlsym(dep->fakeHandle,name);
        void *handle = dlopen(dep->name, RTLD_LAZY);
        if(!handle)
        {
            fprintf(stderr, "relocLibrary error: cannot dlopen a fake object named %s", dep->name);
            abort();
        }
        dep->fakeHandle = handle;
        return dlsym(handle, name);
    }

    Elf64_Sym *symtab = (Elf64_Sym *)dep->dynInfo[DT_SYMTAB]->d_un.d_ptr;
    const char *strtab = (const char *)dep->dynInfo[DT_STRTAB]->d_un.d_ptr;

    uint_fast32_t new_hash = dl_new_hash(name);
    Elf64_Sym *sym;
    const Elf64_Addr *bitmask = dep->l_gnu_bitmask;
    uint32_t symidx;
    Elf64_Addr bitmask_word = bitmask[(new_hash / __ELF_NATIVE_CLASS) & dep->l_gnu_bitmask_idxbits];
    unsigned int hashbit1 = new_hash & (__ELF_NATIVE_CLASS - 1);
    unsigned int hashbit2 = ((new_hash >> dep->l_gnu_shift) & (__ELF_NATIVE_CLASS - 1));
    if ((bitmask_word >> hashbit1) & (bitmask_word >> hashbit2) & 1)
    {
        Elf32_Word bucket = dep->l_gnu_buckets[new_hash % dep->l_nbuckets];
        if (bucket != 0)
        {
            const Elf32_Word *hasharr = &dep->l_gnu_chain_zero[bucket];
            do
            {
                if (((*hasharr ^ new_hash) >> 1) == 0)
                {
                    symidx = hasharr - dep->l_gnu_chain_zero;
                    /* now, symtab[symidx] is the current symbol.
                       Hash table has done its job */
                    const char *symname = strtab + symtab[symidx].st_name;
                    if (!strcmp(symname, name))
                    {    
                        Elf64_Sym *s = &symtab[symidx];
                        // return the real address of found symbol
                        return (void *)(s->st_value + dep->addr);
                    }
                }
            } while ((*hasharr++ & 1u) == 0);
        }
    }
    return NULL; //not this dependency
}

extern void trampoline(void);

void RelocLibrary(LinkMap *lib, int mode)
{
    /* Your code here */
    if(strcmp(lib->name,"lib.so.6")==0)
        return;
    for(int j = 0;j < lib->depcnt; ++j)
        RelocLibrary(lib->dep[j], mode);
//    fprintf(stdout,"Reloc : %s in mode %d\n",lib->name, mode);
    Elf64_Sym *sym=NULL;
    Elf64_Rela *frel=NULL;
    int relsz=0;
    char *str=NULL;
    if(lib->dynInfo[DT_SYMTAB])
        sym=(typeof(sym))lib->dynInfo[DT_SYMTAB]->d_un.d_ptr;
    if(lib->dynInfo[DT_JMPREL])
        frel=(typeof(frel))lib->dynInfo[DT_JMPREL]->d_un.d_ptr;
    if(lib->dynInfo[DT_PLTRELSZ])
        relsz=lib->dynInfo[DT_PLTRELSZ]->d_un.d_val/sizeof(Elf64_Rela);
    if(lib->dynInfo[DT_STRTAB])
        str=(char*)lib->dynInfo[DT_STRTAB]->d_un.d_ptr;
    for(int i=0;i<relsz;++i,++frel){
        if(ELF64_R_TYPE(frel->r_info)!=R_X86_64_JUMP_SLOT)
            continue;
        Elf64_Addr *got=(void*)(lib->addr+frel->r_offset);
        if(mode == RTLD_LAZY){
            *got += lib->addr;
            continue;
        }
        void *result = NULL;
        for(int j=0;j<lib->depcnt;++j){
            void *tmp=symbolLookup(lib->dep[j],&str[sym[ELF64_R_SYM(frel->r_info)].st_name]);
            if(tmp!=NULL){
                result=tmp+frel->r_addend;
                break;
            }
        }
        if(result == NULL){
            fprintf(stderr,"symbol not found");
            abort();
        }
        *(uint64_t*)(lib->addr+frel->r_offset)=(uint64_t)result;
    }
    if(lib->dynInfo[DT_PLTGOT]){
        uint64_t *GOT=(typeof(GOT))lib->dynInfo[DT_PLTGOT]->d_un.d_ptr;
        GOT[1]=(uint64_t)lib;
        GOT[2]=(uint64_t)&trampoline;
    }
//    fprintf(stderr,"%s",lib->name);
//   fprintf(stderr,"\n%p",GOT);
//    abort();
}
