#include <types.h>
#include <mmap.h>
#include <fork.h>
#include <v2p.h>
#include <page.h>

/* 
 * You may define macros and other helper functions here
 * You must not declare and use any static/global variables 
 * */


/**
 * mprotect System call Implementation.
 */

struct vm_area *create_vm_node(u64 start, u64 end, int prot)
{
    struct vm_area *new = (struct vm_area *)os_alloc(sizeof(struct vm_area));
    if(prot == 0){
        stats->num_vm_area = 1;
    }
    else{
        stats->num_vm_area += 1;
    }
    new->vm_next = NULL;
    new->vm_start = start;
    new->vm_end = end;
    new->access_flags = prot;
    return new;
}

void delete_node(struct vm_area *node){
    os_free(node, sizeof(struct vm_area));
    stats->num_vm_area--;
}

void pfn_protect(struct exec_context *current, u64 addr, int length, int prot){
    int len_4kb = (length / 4096) * 4096;
    if(length % 4096){
        len_4kb += 4096;
    }    
    u64 start = addr;
    u64 end = addr + len_4kb;
    struct vm_area *head_vma = current->vm_area;
    struct vm_area *temp_vma = head_vma;
    while (temp_vma != NULL){
        if(temp_vma->vm_end <= start){
            temp_vma = temp_vma->vm_next;
            if(temp_vma == NULL) break;
        }
        for (u64 page_addr = temp_vma->vm_start; page_addr < temp_vma->vm_end; page_addr += 4096){
            if(page_addr >= start && page_addr < end){
                u64 pgd_offset = (page_addr >> 39) & 0x1FF;
                u64 pud_offset = (page_addr >> 30) & 0x1FF;
                u64 pmd_offset = (page_addr >> 21) & 0x1FF;
                u64 pte_offset = (page_addr >> 12) & 0x1FF;

                u64 pgd_entry = 0;
                u64 pud_entry = 0;
                u64 pmd_entry = 0;
                u64 pte_entry = 0;

                u64 *pgd_entry_addr;
                u64 *pud_entry_addr;
                u64 *pmd_entry_addr;
                u64 *pte_entry_addr;

                u64 *pgd;
                u64 *pud;
                u64 *pmd;
                u64 *pte;

                pgd = osmap(current->pgd); 
                pgd_entry_addr = pgd + pgd_offset;
                pgd_entry = *(pgd_entry_addr);

                if(pgd_entry & 1 == 1){
                    pud = osmap((pgd_entry >> 12) & 0xFFFFFFFF);
                    pud_entry_addr = pud + pud_offset;
                    pud_entry = *(pud_entry_addr);
                }
                else{
                    continue; 
                }

                if(pud_entry & 1 == 1){
                    pmd = osmap((pud_entry >> 12) & 0xFFFFFFFF);
                    pmd_entry_addr = pmd + pmd_offset;
                    pmd_entry = *(pmd_entry_addr);
                }
                else{
                    continue;
                }

                if(pmd_entry & 1 == 1){
                    pte = osmap((pmd_entry >> 12) & 0xFFFFFFFF);
                    pte_entry_addr = pte + pte_offset;
                    pte_entry = *(pte_entry_addr);
                }
                else{
                    continue;
                }

                if(pte_entry & 1 == 1){
                    if(get_pfn_refcount(pte_entry >> 12) > 1){
                        if(prot == PROT_READ){
                            *(pte_entry_addr) = *(pte_entry_addr) & (u64)(~(1 << 3));
                        }
                        asm volatile("invlpg (%0)"::"r" (page_addr));
                        return;  
                    }
                    u64 w = 0;
                    if (prot == PROT_READ){
                        w = 0;
                    }
                    else if (prot == (PROT_READ | PROT_WRITE)){
                        w = 1;
                    }

                    if (w == 1){
                        *(pte_entry_addr) = *(pte_entry_addr) | (1 << 3);
                    }

                    else if (w == 0){
                        *(pte_entry_addr) = *(pte_entry_addr) & (u64)(~(1 << 3));
                    }
                    
                    asm volatile("invlpg (%0)"::"r" (page_addr));
                    continue;
                }
                else{
                    continue;
                }


            }
            if(page_addr >= end){
                return;
            }
        }
        temp_vma = temp_vma->vm_next;
    }
}

long vm_area_mprotect(struct exec_context *current, u64 addr, int length, int prot)
{
    pfn_protect(current, addr, length, prot);
    int len_4kb = (length / 4096) * 4096;
    if(length % 4096){
        len_4kb += 4096;
    }
    struct vm_area *before_merge_left = NULL;
    struct vm_area *merge_left = NULL;
    struct vm_area *merge_right = NULL;
    struct vm_area *head_vma = current->vm_area;
    u64 start = addr;
    u64 end = addr + len_4kb;

    struct vm_area *temp_vma = head_vma;
    while (temp_vma != NULL){
        if(start >= temp_vma->vm_start && start <= temp_vma->vm_end && end >= temp_vma->vm_start && end <= temp_vma->vm_end){
            if(prot == temp_vma->access_flags) return 0;
            if(start == temp_vma->vm_start && end == temp_vma->vm_end){
                merge_left = temp_vma;
                merge_right = temp_vma->vm_next;
                break;
            }
            else if(start == temp_vma->vm_start){
                struct vm_area *new_vma = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                new_vma->vm_start = end;
                new_vma->vm_end = temp_vma->vm_end;
                temp_vma->vm_end = end;
                new_vma->access_flags = temp_vma->access_flags;
                temp_vma->access_flags = prot;
                new_vma->vm_next = temp_vma->vm_next;
                temp_vma->vm_next = new_vma;
                merge_left = temp_vma;
                merge_right = new_vma;
                stats->num_vm_area ++;
                break;
            }
            else if(end == temp_vma->vm_end){
                struct vm_area *new_vma = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                new_vma->vm_start = end;
                new_vma->vm_end = temp_vma->vm_end;
                temp_vma->vm_end = end;
                new_vma->access_flags = prot;
                new_vma->vm_next = temp_vma->vm_next;
                temp_vma->vm_next = new_vma;
                merge_left = new_vma;
                merge_right = new_vma->vm_next;
                stats->num_vm_area ++;

                break;
            }
            else{
                struct vm_area *new_vma_mid = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                new_vma_mid->vm_start = start;
                new_vma_mid->vm_end = end;
                new_vma_mid->access_flags = prot;
                struct vm_area *new_vma_right = (struct vm_area *)os_alloc(sizeof(struct vm_area));
                new_vma_right->vm_start = end;
                new_vma_right->vm_end = temp_vma->vm_end;
                temp_vma->vm_end = start;
                new_vma_right->vm_next = temp_vma->vm_next;
                temp_vma->vm_next = new_vma_mid;
                new_vma_mid->vm_next = new_vma_right;
                new_vma_right->access_flags = temp_vma->access_flags;
                stats->num_vm_area += 2;
                return 0;
            }

        }
        if(start > temp_vma->vm_start && start < temp_vma->vm_end && merge_left == NULL){
            struct vm_area *new_vma = (struct vm_area *)os_alloc(sizeof(struct vm_area));
            new_vma->vm_start = start;
            new_vma->vm_end = temp_vma->vm_end;
            temp_vma->vm_end = start;
            new_vma->access_flags = prot;
            new_vma->vm_next = temp_vma->vm_next;
            temp_vma->vm_next = new_vma;
            merge_left = temp_vma->vm_next;
            stats->num_vm_area ++;

        }

        else if(start <= temp_vma->vm_start && merge_left == NULL){
            temp_vma->access_flags = prot;
            merge_left = temp_vma;
        }

        if(end > temp_vma->vm_start && end < temp_vma->vm_end && merge_right == NULL){
            struct vm_area *new_vma = (struct vm_area *)os_alloc(sizeof(struct vm_area));
            new_vma->vm_start = end;
            new_vma->vm_end = temp_vma->vm_end;
            temp_vma->vm_end = end;
            new_vma->access_flags = temp_vma->access_flags;
            temp_vma->access_flags = prot;
            new_vma->vm_next = temp_vma->vm_next;
            temp_vma->vm_next = new_vma;
            merge_right = new_vma;
            stats->num_vm_area ++;
        }

        else if(end <= temp_vma->vm_start && merge_right == NULL){
            merge_right = temp_vma;

        }

        else if(end == temp_vma->vm_end && merge_right == NULL){
            temp_vma->access_flags = prot;
            merge_right = temp_vma->vm_next;
        }

        temp_vma = temp_vma->vm_next;
    }

    if(merge_left == NULL){
        return 0;
    }

    temp_vma = head_vma;
    while (temp_vma->vm_next != NULL){
        if(temp_vma->vm_next == merge_left){
            before_merge_left = temp_vma;
            break;
        }
        temp_vma = temp_vma->vm_next;
    }

    temp_vma = merge_left;
    while(temp_vma != merge_right){
        temp_vma->access_flags = prot;
        temp_vma = temp_vma->vm_next;
    }

    temp_vma = before_merge_left;
    
    while(temp_vma != merge_right && temp_vma->vm_next != NULL && temp_vma->vm_end != merge_right->vm_end){ 
        if(temp_vma->vm_end == temp_vma->vm_next->vm_start && temp_vma->access_flags == temp_vma->vm_next->access_flags){
            temp_vma->vm_end = temp_vma->vm_next->vm_end;
            struct vm_area *delete_vm = temp_vma->vm_next;
            temp_vma->vm_next = temp_vma->vm_next->vm_next;
            os_free(delete_vm, sizeof(struct vm_area));
            stats->num_vm_area--;
            continue;
        }

        temp_vma = temp_vma->vm_next;
    }
    return 0;

}

/**
 * mmap system call implementation.
 */

long vm_area_map(struct exec_context *current, u64 addr, int length, int prot, int flags)
{
    if((!(flags == 0 || flags == MAP_FIXED)) || (!(prot == PROT_READ || (prot == (PROT_READ | PROT_WRITE)))) || (addr != 0 && (addr < MMAP_AREA_START + 4096 || addr >= MMAP_AREA_END)) || (length > 0x200000 || length <= 0)){
        return -1;
    }
    int len_4kb = (length / 4096) * 4096;
    if(length % 4096){
        len_4kb += 4096;
    }
    struct vm_area *head_vma = current->vm_area;
    if(head_vma == NULL){ 
        struct vm_area *dummy = create_vm_node(MMAP_AREA_START, MMAP_AREA_START + 4096, 0);
        head_vma = dummy;
        current->vm_area = dummy;
        stats->num_vm_area = 1;
    }

    if(addr != 0 && flags == MAP_FIXED){ 
        struct vm_area *temp_vma = head_vma;
        while(temp_vma != NULL){
            if(temp_vma->vm_next != NULL){ 
                if((addr >= temp_vma->vm_end && addr + len_4kb <= temp_vma->vm_next->vm_start) && (temp_vma->vm_next->vm_start - temp_vma->vm_end >= len_4kb)){
                    int found1 = 0, found2 = 0;
                    if(temp_vma->vm_end == addr && temp_vma->access_flags == prot){
                        found1 = 1;
                    }
                    if(temp_vma->vm_next->vm_start == addr + len_4kb && temp_vma->vm_next->access_flags == prot){
                        found2 = 1;
                    }
                    if(found1 && found2){
                        temp_vma->vm_end = temp_vma->vm_next->vm_end;
                        struct vm_area *delete_vm = temp_vma->vm_next;
                        temp_vma->vm_next = temp_vma->vm_next->vm_next;
                        delete_node(delete_vm);
                    }                    
                    else if(found1){
                        temp_vma->vm_end = temp_vma->vm_end + len_4kb;
                    }
                    else if(found2){
                        temp_vma->vm_next->vm_start = temp_vma->vm_next->vm_start - len_4kb;
                    }
                    else{
                        struct vm_area *new_vma = create_vm_node(addr, addr + len_4kb, prot);
                        new_vma->vm_next = temp_vma->vm_next;
                        temp_vma->vm_next = new_vma;
                    }
                    return addr;                     
                }
            }
            else if(temp_vma->vm_next == NULL){ 
                if((addr >= temp_vma->vm_end && addr + len_4kb < MMAP_AREA_END) && (MMAP_AREA_END - temp_vma->vm_end > len_4kb)){ 
                    int found = 0;
                    if(temp_vma->vm_end == addr){
                        if(temp_vma->access_flags == prot){
                            found = 1;
                        }
                    }
                    if(found){
                        temp_vma->vm_end = temp_vma->vm_end + len_4kb;
                    }
                    else{
                        struct vm_area *new_vma = create_vm_node(addr, addr + len_4kb, prot);
                        new_vma->vm_next = temp_vma->vm_next;
                        temp_vma->vm_next = new_vma;
                    }
                    return addr;  
                }
            }
            temp_vma = temp_vma->vm_next;
        }
    }
    else if(addr == 0){ 
        struct vm_area *temp_vma = head_vma;
        while(temp_vma != NULL){
            if(temp_vma->vm_next != NULL){ 
                if(temp_vma->vm_next->vm_start - temp_vma->vm_end >= len_4kb){
                    u64 map_ret = temp_vma->vm_end;                        
                    int found1 = 0, found2 = 0; 
                    if(temp_vma->access_flags == prot){
                        found1 = 1;
                    }
                    if(temp_vma->vm_next->vm_start == temp_vma->vm_end + len_4kb && temp_vma->vm_next->access_flags == prot){
                        found2 = 1;
                    }
                    if(found1 && found2){
                        temp_vma->vm_end = temp_vma->vm_next->vm_end;
                        struct vm_area *delete_vm = temp_vma->vm_next;
                        temp_vma->vm_next = temp_vma->vm_next->vm_next;
                        delete_node(delete_vm);
                    }
                    else if(found1){
                        temp_vma->vm_end = temp_vma->vm_end + len_4kb;
                    }
                    else if(found2){
                        temp_vma->vm_next->vm_start = temp_vma->vm_next->vm_start - len_4kb;
                    }
                    else{
                        struct vm_area *new_vma = create_vm_node(temp_vma->vm_end, temp_vma->vm_end + len_4kb, prot);
                        new_vma->vm_next = temp_vma->vm_next;
                        temp_vma->vm_next = new_vma;
                    }
                    return map_ret;
                }
            }
            else if(temp_vma->vm_next == NULL){ 
                if(MMAP_AREA_END - temp_vma->vm_end >= len_4kb){ 
                    u64 map_ret = temp_vma->vm_end;
                    int found = 0;
                    if(temp_vma->access_flags == prot){
                        found = 1;
                    }
                    if(found){
                        temp_vma->vm_end = temp_vma->vm_end + len_4kb;
                    }
                    else{
                        struct vm_area *new_vma = create_vm_node(temp_vma->vm_end, temp_vma->vm_end + len_4kb, prot);
                        new_vma->vm_next = temp_vma->vm_next;
                        temp_vma->vm_next = new_vma;
                    }
                    return map_ret;
                }
            }
            temp_vma = temp_vma->vm_next;
        }
    }

    else if(addr != 0 && flags == 0){ 
        struct vm_area *temp_vma = head_vma;
        while(temp_vma != NULL){
            if((temp_vma->vm_next != NULL) && (addr >= temp_vma->vm_end) && (addr + len_4kb - 1 < temp_vma->vm_next->vm_start) && (temp_vma->vm_next->vm_start - temp_vma->vm_end >= len_4kb)){ 
                int found1 = 0, found2 = 0;
                if(temp_vma->vm_end == addr && temp_vma->access_flags == prot){
                    found1 = 1;
                }               
                if(temp_vma->vm_next->vm_start == addr + len_4kb && temp_vma->vm_next->access_flags == prot){
                    found2 = 1;
                }
                if(found1 && found2){
                    temp_vma->vm_end = temp_vma->vm_next->vm_end;
                    struct vm_area *delete_vm = temp_vma->vm_next;
                    temp_vma->vm_next = temp_vma->vm_next->vm_next;
                    delete_node(delete_vm);
                }                
                else if(found1){
                    temp_vma->vm_end = temp_vma->vm_end + len_4kb;
                }
                else if(found2){
                    temp_vma->vm_next->vm_start = temp_vma->vm_next->vm_start - len_4kb;
                }
                else{
                    struct vm_area *new_vma = create_vm_node(addr, addr + len_4kb, prot);
                    new_vma->vm_next = temp_vma->vm_next;
                    temp_vma->vm_next = new_vma;
                }
                return addr;               
            }

            else if(temp_vma->vm_next == NULL){ 
                if(MMAP_AREA_END - temp_vma->vm_end > len_4kb && addr >= temp_vma->vm_end && addr + len_4kb <= MMAP_AREA_END){ 
                    int found = 0;
                    if(temp_vma->vm_end == addr && temp_vma->access_flags == prot){
                        found = 1;
                    }
                    if(found){
                        temp_vma->vm_end = temp_vma->vm_end + len_4kb;
                    }
                    else{
                        struct vm_area *new_vma = create_vm_node(addr, addr + len_4kb, prot);
                        new_vma->vm_next = temp_vma->vm_next;
                        temp_vma->vm_next = new_vma;
                    }
                    return addr;                    
                }
            }
            temp_vma = temp_vma->vm_next;
        }
        temp_vma = head_vma;        
        while(temp_vma != NULL){
            if(temp_vma->vm_next != NULL){
                if(temp_vma->vm_next->vm_start - temp_vma->vm_end >= len_4kb){
                    u64 map_ret = temp_vma->vm_end;
                    int found1 = 0, found2 = 0;
                    if(temp_vma->access_flags == prot){
                        found1 = 1;
                    }
                    if(temp_vma->vm_next->vm_start == temp_vma->vm_end + len_4kb && temp_vma->vm_next->access_flags == prot){
                        found2 = 1;
                    }
                    if(found1 && found2){
                        temp_vma->vm_end = temp_vma->vm_next->vm_end;
                        struct vm_area *delete_vm = temp_vma->vm_next;
                        temp_vma->vm_next = temp_vma->vm_next->vm_next;
                        delete_node(delete_vm);
                    }
                    else if(found1){
                        temp_vma->vm_end = temp_vma->vm_end + len_4kb;
                    }

                    else if(found2){
                        temp_vma->vm_next->vm_start = temp_vma->vm_next->vm_start - len_4kb;
                    }

                    else{
                        struct vm_area *new_vma = create_vm_node(temp_vma->vm_end, temp_vma->vm_end + len_4kb, prot);
                        new_vma->vm_next = temp_vma->vm_next;
                        temp_vma->vm_next = new_vma;
                    }
                    return map_ret;
                }

                
            }

            else if(temp_vma->vm_next == NULL){ 
                if(MMAP_AREA_END - temp_vma->vm_end > len_4kb){ 
                    u64 map_ret = temp_vma->vm_end;
                    int found = 0;
                    if(temp_vma->access_flags == prot){
                        found = 1;
                    }
                    if(found){
                        temp_vma->vm_end = temp_vma->vm_end + len_4kb;
                    }
                    else{
                        struct vm_area *new_vma = create_vm_node(temp_vma->vm_end, temp_vma->vm_end + len_4kb, prot);
                        new_vma->vm_next = temp_vma->vm_next;
                        temp_vma->vm_next = new_vma;
                    }
                    return map_ret;
                }
            }

            temp_vma = temp_vma->vm_next;
        }
    }
    


    return -1;
}

/**
 * munmap system call implemenations
 */

void pfn_unmap(struct exec_context *current, u64 addr, int length){
    int len_4kb = (length / 4096) * 4096;
    if(length % 4096){
        len_4kb += 4096;
    }
    u64 start = addr;
    u64 end = addr + len_4kb;

    struct vm_area *head_vma = current->vm_area;
    struct vm_area *temp_vma = head_vma;
    while (temp_vma != NULL){
        if(temp_vma->vm_end <= start){
            temp_vma = temp_vma->vm_next;
            if(temp_vma == NULL) break;
        }
        for (u64 page_addr = temp_vma->vm_start; page_addr < temp_vma->vm_end; page_addr += 4096){
            if(page_addr >= start && page_addr < end){
                u64 pgd_offset = (page_addr >> 39) & 0x1FF;
                u64 pud_offset = (page_addr >> 30) & 0x1FF;
                u64 pmd_offset = (page_addr >> 21) & 0x1FF;
                u64 pte_offset = (page_addr >> 12) & 0x1FF;

                u64 pgd_entry = 0;
                u64 pud_entry = 0;
                u64 pmd_entry = 0;
                u64 pte_entry = 0;

                u64 *pgd_entry_addr;
                u64 *pud_entry_addr;
                u64 *pmd_entry_addr;
                u64 *pte_entry_addr;

                u64 *pgd;
                u64 *pud;
                u64 *pmd;
                u64 *pte;

                pgd = osmap(current->pgd); 
                pgd_entry_addr = pgd + pgd_offset;
                pgd_entry = *(pgd_entry_addr);

                if(pgd_entry & 1 == 1){
                    pud = osmap((pgd_entry >> 12) & 0xFFFFFFFF);
                    pud_entry_addr = pud + pud_offset;
                    pud_entry = *(pud_entry_addr);
                }
                else{
                    continue;
                }

                if(pud_entry & 1 == 1){
                    pmd = osmap((pud_entry >> 12) & 0xFFFFFFFF);
                    pmd_entry_addr = pmd + pmd_offset;
                    pmd_entry = *(pmd_entry_addr);
                }
                else{
                    continue;
                }

                if(pmd_entry & 1 == 1){
                    pte = osmap((pmd_entry >> 12) & 0xFFFFFFFF);
                    pte_entry_addr = pte + pte_offset;
                    pte_entry = *(pte_entry_addr);
                }
                else{
                    continue;
                }

                if(pte_entry & 1 == 1){
                    if(get_pfn_refcount(pte_entry >> 12) == 1){
                        put_pfn(pte_entry >> 12);
                        os_pfn_free(USER_REG, (u64)((pte_entry >> 12) & 0xFFFFFFFF));
                        *(pte_entry_addr) = 0;
                    }
                    else{
                        put_pfn(pte_entry >> 12); 
                        *(pte_entry_addr) = 0;
                    }
                    asm volatile("invlpg (%0)"::"r" (page_addr));
                    continue;
                }
                else{
                    continue;
                }


            }
            if(page_addr >= end){
                return;
            }
        }
        temp_vma = temp_vma->vm_next;
    }
}

long vm_area_unmap(struct exec_context *current, u64 addr, int length)
{

    pfn_unmap(current, addr, length);
    int len_4kb = (length / 4096) * 4096;
    if(length % 4096){
        len_4kb += 4096;
    }
    u64 start = addr;
    u64 end = addr + len_4kb;
    struct vm_area *merge_left = NULL;
    struct vm_area *merge_right = NULL;
    struct vm_area *head_vma = current->vm_area;
    struct vm_area *temp_vma = head_vma;
    while (temp_vma != NULL){
        if(start >= temp_vma->vm_start && start <= temp_vma->vm_end && end >= temp_vma->vm_start && end <= temp_vma->vm_end){
            if(start == temp_vma->vm_start && end == temp_vma->vm_end){
                merge_left = temp_vma;
                merge_right = temp_vma->vm_next;
                break;
            }
            else if(start == temp_vma->vm_start){
                temp_vma->vm_start = end;
                return 0;
            }
            else if(end == temp_vma->vm_end){
                temp_vma->vm_end = start;
                return 0;
            }
            else{
                struct vm_area *new_vma = create_vm_node(end, temp_vma->vm_end, temp_vma->access_flags);
                temp_vma->vm_end = start;
                new_vma->vm_next = temp_vma->vm_next;
                temp_vma->vm_next = new_vma;
                return 0;
            }

        }
        if(start > temp_vma->vm_start && start < temp_vma->vm_end && merge_left == NULL){
            temp_vma->vm_end = start;
            merge_left = temp_vma->vm_next;
        }
        else if(start <= temp_vma->vm_start && merge_left == NULL){
            merge_left = temp_vma;
        }
        if(end > temp_vma->vm_start && end < temp_vma->vm_end && merge_right == NULL){
            merge_right = temp_vma;
            temp_vma->vm_start = end;
        }
        else if(end <= temp_vma->vm_start && merge_right == NULL){
            merge_right = temp_vma;

        }
        else if(end == temp_vma->vm_end && merge_right == NULL){
            merge_right = temp_vma->vm_next;
        }
        temp_vma = temp_vma->vm_next;

    }

    if(merge_left == NULL){
        return 0;
    }

    temp_vma = head_vma;
    while (temp_vma->vm_next != NULL){
        if(temp_vma->vm_next == merge_left){
            temp_vma->vm_next = merge_right;
            break;
        }
        temp_vma = temp_vma->vm_next;
    }

    temp_vma = merge_left;
    while(temp_vma != merge_right){
        struct vm_area *next_vm = temp_vma->vm_next;
        delete_node(temp_vma);
        temp_vma = next_vm;
    }

    return 0;
}



/**
 * Function will invoked whenever there is page fault for an address in the vm area region
 * created using mmap
 */

long vm_area_pagefault(struct exec_context *current, u64 addr, int error_code)
{
    int p, w, u;
    u = (error_code & 4) >> 2;
    w = (error_code & 2) >> 1; 
    p = error_code & 1;
    int access;
    if(w == 0) {
        access = 1;
    }
    else{
        access = 3;
    } 

    u64 pgd_offset = (addr >> 39) & 0x1FF;
    u64 pud_offset = (addr >> 30) & 0x1FF;
    u64 pmd_offset = (addr >> 21) & 0x1FF;
    u64 pte_offset = (addr >> 12) & 0x1FF;

    u64 pgd_entry = 0;
    u64 pud_entry = 0;
    u64 pmd_entry = 0;
    u64 pte_entry = 0;

    u64 *pgd_entry_addr;
    u64 *pud_entry_addr;
    u64 *pmd_entry_addr;
    u64 *pte_entry_addr;

    u64 *pgd;
    u64 *pud;
    u64 *pmd;
    u64 *pte;

    struct vm_area *head_vma = current->vm_area;
    struct vm_area *temp_vma = head_vma;
    while(temp_vma != NULL){
        if(addr >= temp_vma->vm_start && addr < temp_vma->vm_end){
            if(temp_vma->access_flags == access){
                if(error_code == 0x7 && temp_vma->access_flags == PROT_READ){
                    return -1;
                }
                if(error_code == 0x7 && temp_vma->access_flags == PROT_READ | PROT_WRITE){
                    handle_cow_fault(current, addr, temp_vma->access_flags);
                    return 1;
                }
                pgd = osmap(current->pgd); 
                pgd_entry_addr = pgd + pgd_offset;
                pgd_entry = *(pgd_entry_addr);

                if(pgd_entry & 1 == 1){
                    *(pgd_entry_addr) = *(pgd_entry_addr) | (1 << 3) | (1 << 0) | (1 << 4);
                    asm volatile("invlpg (%0)"::"r" (addr));
                    pud = osmap((pgd_entry >> 12) & 0xFFFFFFFF);
                    pud_entry_addr = pud + pud_offset;
                    pud_entry = *(pud_entry_addr);
                } 
                else{
                    u32 pud_physical = os_pfn_alloc(OS_PT_REG);
                    *(pgd_entry_addr) = (pud_physical << 12) | (1 << 3) | (1 << 0) | (1 << 4);
                    asm volatile("invlpg (%0)"::"r" (addr));
                    pud = osmap(pud_physical);
                    pud_entry_addr = pud + pud_offset;
                    pud_entry = *(pud_entry_addr);
                }
                
                if(pud_entry & 1 == 1){
                    *(pud_entry_addr) = *(pud_entry_addr) | (1 << 3) | (1 << 0) | (1 << 4);
                    asm volatile("invlpg (%0)"::"r" (addr));
                    pmd = osmap((pud_entry >> 12) & 0xFFFFFFFF);
                    pmd_entry_addr = pmd + pmd_offset;
                    pmd_entry = *(pmd_entry_addr);
                }
                else{
                    u32 pmd_physical = os_pfn_alloc(OS_PT_REG);
                    *(pud_entry_addr) = (pmd_physical << 12) | (1 << 3) | (1 << 0) | (1 << 4);
                    asm volatile("invlpg (%0)"::"r" (addr));
                    pmd = osmap(pmd_physical);
                    pmd_entry_addr = pmd + pmd_offset;
                    pmd_entry = *(pmd_entry_addr);
                }

                if(pmd_entry & 1 == 1){
                    *(pmd_entry_addr) = *(pmd_entry_addr) | (1 << 3) | (1 << 0) | (1 << 4);
                    asm volatile("invlpg (%0)"::"r" (addr));
                    pte = osmap((pmd_entry >> 12) & 0xFFFFFFFF);
                    pte_entry_addr = pte + pte_offset;
                    pte_entry = *(pte_entry_addr);
                }
                else{
                    u32 pte_physical = os_pfn_alloc(OS_PT_REG);
                    *(pmd_entry_addr) = (pte_physical << 12) | (1 << 3) | (1 << 0) | (1 << 4);
                    asm volatile("invlpg (%0)"::"r" (addr));
                    pte = osmap(pte_physical);
                    pte_entry_addr = pte + pte_offset;
                    pte_entry = *(pte_entry_addr);
                }

                if(pte_entry & 1 == 1){
                    *(pte_entry_addr) = *(pte_entry_addr) | (w << 3) | (1 << 0) | (1 << 4);
                    asm volatile("invlpg (%0)"::"r" (addr));
                    return 1;
                }
                else{
                    u32 pfn_physical = os_pfn_alloc(USER_REG);
                    *(pte_entry_addr) = (pfn_physical << 12) | (w << 3) | (1 << 0) | (1 << 4);
                    asm volatile("invlpg (%0)"::"r" (addr));
                    return 1;
                }


            }
        }
        temp_vma = temp_vma->vm_next;
    }
    return -1;
}



void create_pt_entry(u64 page_addr, struct exec_context *ctx, struct exec_context *new_ctx){
    u64 pgd_offset = (page_addr >> 39) & 0x1FF;
    u64 pud_offset = (page_addr >> 30) & 0x1FF;
    u64 pmd_offset = (page_addr >> 21) & 0x1FF;
    u64 pte_offset = (page_addr >> 12) & 0x1FF;

    u64 pgd_entry_c = 0;
    u64 pud_entry_c = 0;
    u64 pmd_entry_c = 0;
    u64 pte_entry_c = 0;

    u64 *pgd_entry_addr_c;
    u64 *pud_entry_addr_c;
    u64 *pmd_entry_addr_c;
    u64 *pte_entry_addr_c;

    u64 *pgd_c;
    u64 *pud_c;
    u64 *pmd_c;
    u64 *pte_c;

    u64 pgd_entry_p = 0;
    u64 pud_entry_p = 0;
    u64 pmd_entry_p = 0;
    u64 pte_entry_p = 0;

    u64 *pgd_entry_addr_p;
    u64 *pud_entry_addr_p;
    u64 *pmd_entry_addr_p;
    u64 *pte_entry_addr_p;

    u64 *pgd_p;
    u64 *pud_p;
    u64 *pmd_p;
    u64 *pte_p;

    pgd_c = osmap(new_ctx->pgd);
    pgd_p = osmap(ctx->pgd);
    pgd_entry_addr_c = pgd_c + pgd_offset;
    pgd_entry_addr_p = pgd_p + pgd_offset;
    pgd_entry_c = *(pgd_entry_addr_c);
    pgd_entry_p = *(pgd_entry_addr_p);

    if(pgd_entry_p & 1 == 1){
        pud_p = osmap((pgd_entry_p >> 12) & 0xFFFFFFFF);
        pud_entry_addr_p = pud_p + pud_offset;
        pud_entry_p = *(pud_entry_addr_p);
        if(pgd_entry_c & 1 == 1){
            *(pgd_entry_addr_c) = *(pgd_entry_addr_c) | (1 << 3) | (1 << 0) | (1 << 4);
            asm volatile("invlpg (%0)"::"r" (page_addr));
            pud_c = osmap((pgd_entry_c >> 12) & 0xFFFFFFFF);
            pud_entry_addr_c = pud_c + pud_offset;
            pud_entry_c = *(pud_entry_addr_c);
        }
        else{
            u32 pud_c_physical = os_pfn_alloc(OS_PT_REG);
            *(pgd_entry_addr_c) = (pud_c_physical << 12) | (1 << 3) | (1 << 0) | (1 << 4);
            asm volatile("invlpg (%0)"::"r" (page_addr));
            pud_c = osmap(pud_c_physical);
            pud_entry_addr_c = pud_c + pud_offset;
            pud_entry_c = *(pud_entry_addr_c);
        }
    }
    else{
        *(pgd_entry_addr_c) = *(pgd_entry_addr_c) & (~(1 << 0));
        asm volatile("invlpg (%0)"::"r" (page_addr));
        return;
    }

    if(pud_entry_p & 1 == 1){
        pmd_p = osmap((pud_entry_p >> 12) & 0xFFFFFFFF);
        pmd_entry_addr_p = pmd_p + pmd_offset;
        pmd_entry_p = *(pmd_entry_addr_p);
        if(pud_entry_c & 1 == 1){
            *(pud_entry_addr_c) = *(pud_entry_addr_c) | (1 << 3) | (1 << 0) | (1 << 4);
            asm volatile("invlpg (%0)"::"r" (page_addr));
            pmd_c = osmap((pud_entry_c >> 12) & 0xFFFFFFFF);
            pmd_entry_addr_c = pmd_c + pmd_offset;
            pmd_entry_c = *(pmd_entry_addr_c);
        }
        else{
            u32 pmd_c_physical = os_pfn_alloc(OS_PT_REG);
            *(pud_entry_addr_c) = (pmd_c_physical << 12) | (1 << 3) | (1 << 0) | (1 << 4);
            asm volatile("invlpg (%0)"::"r" (page_addr));
            pmd_c = osmap(pmd_c_physical);
            pmd_entry_addr_c = pmd_c + pmd_offset;
            pmd_entry_c = *(pmd_entry_addr_c);
        }
    }
    else{
        *(pud_entry_addr_c) = *(pud_entry_addr_c) & (~(1 << 0));
        asm volatile("invlpg (%0)"::"r" (page_addr));
        return;
    }

    if(pmd_entry_p & 1 == 1){
        pte_p = osmap((pmd_entry_p >> 12) & 0xFFFFFFFF);
        pte_entry_addr_p = pte_p + pte_offset;
        pte_entry_p = *(pte_entry_addr_p);
        if(pmd_entry_c & 1 == 1){
            *(pmd_entry_addr_c) = *(pmd_entry_addr_c) | (1 << 3) | (1 << 0) | (1 << 4);
            asm volatile("invlpg (%0)"::"r" (page_addr));
            pte_c = osmap((pmd_entry_c >> 12) & 0xFFFFFFFF);
            pte_entry_addr_c = pte_c + pte_offset;
            pte_entry_c = *(pte_entry_addr_c);
        }
        else{
            u32 pte_c_physical = os_pfn_alloc(OS_PT_REG);
            *(pmd_entry_addr_c) = (pte_c_physical << 12) | (1 << 3) | (1 << 0) | (1 << 4);
            asm volatile("invlpg (%0)"::"r" (page_addr));
            pte_c = osmap(pte_c_physical);
            pte_entry_addr_c = pte_c + pte_offset;
            pte_entry_c = *(pte_entry_addr_c);
        }
    }
    else{
        *(pmd_entry_addr_c) = *(pmd_entry_addr_c) & (~(1 << 0));
        asm volatile("invlpg (%0)"::"r" (page_addr));
        return;
    }

    if(pte_entry_p & 1 == 1){
        *(pte_entry_addr_p) = *(pte_entry_addr_p) & (~(1 << 3));
        *(pte_entry_addr_p) = *(pte_entry_addr_p) | (1 << 0) | (1 << 4);
        *(pte_entry_addr_c) = *(pte_entry_addr_p);
        get_pfn(pte_entry_p >> 12);
        asm volatile("invlpg (%0)"::"r" (page_addr));
    }
    else{
        *(pte_entry_addr_c) = *(pte_entry_addr_c) & (~(1 << 0));
        asm volatile("invlpg (%0)"::"r" (page_addr));
        return;
    }

    return;
}
/**
 * cfork system call implemenations
 * The parent returns the pid of child process. The return path of
 * the child process is handled separately through the calls at the 
 * end of this function (e.g., setup_child_context etc.)
 */

long do_cfork(){
    u32 pid;
    struct exec_context *new_ctx = get_new_ctx();
    struct exec_context *ctx = get_current_ctx();
     /* Do not modify above lines
     * 
     * */   
     /*--------------------- Your code [start]---------------*/
     
    pid = new_ctx->pid;
    new_ctx->ppid = ctx->pid;
    new_ctx->type = ctx->type;
    new_ctx->state = ctx->state;
    new_ctx->used_mem = ctx->used_mem;
    new_ctx->os_stack_pfn = ctx->os_stack_pfn;
    new_ctx->os_rsp = ctx->os_rsp;
    new_ctx->regs = ctx->regs;
    for(int i = 0; i < MAX_MM_SEGS; i++){
        new_ctx->mms[i] = ctx->mms[i];
    }
    new_ctx->pending_signal_bitmap = ctx->pending_signal_bitmap;
    new_ctx->ticks_to_sleep = ctx->ticks_to_sleep;
    new_ctx->alarm_config_time = ctx->alarm_config_time;
    for(int i = 0; i < CNAME_MAX; i++){
        new_ctx->name[i] = ctx->name[i];
    }
    new_ctx->ticks_to_alarm = ctx->ticks_to_alarm;
    new_ctx->ctx_threads = ctx->ctx_threads;
    for(int i = 0; i < MAX_SIGNALS; i++){
        new_ctx->sighandlers[i] = ctx->sighandlers[i];
    }
    for(int i = 0; i < MAX_OPEN_FILES; i++){
        new_ctx->files[i] = ctx->files[i];
    }
    struct vm_area *vm_area_parent = ctx->vm_area;
    struct vm_area *temp_vma_p = vm_area_parent;
    new_ctx->vm_area = NULL;
    if(temp_vma_p != NULL){
        struct vm_area *dummy_node = (struct vm_area *)os_alloc(sizeof(struct vm_area));
        dummy_node->vm_start = MMAP_AREA_START;
        dummy_node->vm_end = MMAP_AREA_START + 4096;
        dummy_node->access_flags = 0;
        dummy_node->vm_next = NULL;
        new_ctx->vm_area = dummy_node;
        struct vm_area *vm_area_child = new_ctx->vm_area;
        struct vm_area *temp_vma_c = vm_area_child;
        while (temp_vma_p != NULL){
            struct vm_area *new_vma_c = (struct vm_area *)os_alloc(sizeof(struct vm_area));
            new_vma_c->vm_start = temp_vma_p->vm_start;
            new_vma_c->vm_end = temp_vma_p->vm_end;
            new_vma_c->access_flags = temp_vma_p->access_flags;
            temp_vma_c->vm_next = new_vma_c;
            temp_vma_c = new_vma_c;
            temp_vma_p = temp_vma_p->vm_next;
        }
        temp_vma_c->vm_next = NULL;
    }
    new_ctx->pgd = os_pfn_alloc(OS_PT_REG); 
    if(new_ctx->pgd == 0){
        return -1;
    }
    if(vm_area_parent != NULL){
        struct vm_area* temp_vma_p = vm_area_parent->vm_next;
        while (temp_vma_p != NULL){
            for(u64 page_addr = temp_vma_p->vm_start; page_addr < temp_vma_p->vm_end; page_addr += 4096){
                create_pt_entry(page_addr, ctx, new_ctx);
            }
            temp_vma_p = temp_vma_p->vm_next;
        }  
    }
    for(int i = 0; i < 3; i++){        
        for(u64 page_addr = ctx->mms[i].start; page_addr < ctx->mms[i].next_free; page_addr += 4096){
            create_pt_entry(page_addr, ctx, new_ctx);
        }
    }
    for(u64 page_addr = ctx->mms[3].start; page_addr < ctx->mms[3].end; page_addr += 4096){
        create_pt_entry(page_addr, ctx, new_ctx);
    }   

     /*--------------------- Your code [end] ----------------*/
    
     /*
     * The remaining part must not be changed
     */
    copy_os_pts(ctx->pgd, new_ctx->pgd);
    do_file_fork(new_ctx);
    setup_child_context(new_ctx);
    return pid;
}





/* Cow fault handling, for the entire user address space
 * For address belonging to memory segments (i.e., stack, data) 
 * it is called when there is a CoW violation in these areas. 
 *
 * For vm areas, your fault handler 'vm_area_pagefault'
 * should invoke this function
 * */

long handle_cow_fault(struct exec_context *current, u64 vaddr, int access_flags)
{
    u64 *pgd;
    u64 *pud;
    u64 *pmd;
    u64 *pte;

    u64 pgd_offset = (vaddr >> 39) & 0x1FF;
    u64 pud_offset = (vaddr >> 30) & 0x1FF;
    u64 pmd_offset = (vaddr >> 21) & 0x1FF;
    u64 pte_offset = (vaddr >> 12) & 0x1FF;

    u64 pgd_entry = 0;
    u64 pud_entry = 0;
    u64 pmd_entry = 0;
    u64 pte_entry = 0;

    u64 *pgd_entry_addr;
    u64 *pud_entry_addr;
    u64 *pmd_entry_addr;
    u64 *pte_entry_addr;

    pgd = osmap(current->pgd);
    pgd_entry_addr = pgd + pgd_offset;
    pgd_entry = *(pgd_entry_addr);

    if(pgd_entry & 1 == 1){
        pud = osmap((pgd_entry >> 12) & 0xFFFFFFFF);
        pud_entry_addr = pud + pud_offset;
        pud_entry = *(pud_entry_addr);
    }
    else{
        return -1; 
    }
    
    if(pud_entry & 1 == 1){
        pmd = osmap((pud_entry >> 12) & 0xFFFFFFFF);
        pmd_entry_addr = pmd + pmd_offset;
        pmd_entry = *(pmd_entry_addr);
    }
    else{
        return -1;
    }

    if(pmd_entry & 1 == 1){
        pte = osmap((pmd_entry >> 12) & 0xFFFFFFFF);
        pte_entry_addr = pte + pte_offset;
        pte_entry = *(pte_entry_addr);
    }
    else{
        return -1;
    }

    if(pte_entry & 1 == 1){
        int ref_count = get_pfn_refcount((pte_entry >> 12) & 0xFFFFFFFF);
        if(ref_count > 1){
            u32 pfn = os_pfn_alloc(USER_REG);
            if(pfn == 0) return -1;
            put_pfn((pte_entry >> 12) & 0xFFFFFFFF);
            memcpy((char*)osmap(pfn), (char*)osmap((pte_entry >> 12) & 0xFFFFFFFF), 4096);
            *(pte_entry_addr) = (pfn << 12) | (*(pte_entry_addr) & 0xFFF);
            if(access_flags == (PROT_READ | PROT_WRITE)){
                *(pte_entry_addr) = *(pte_entry_addr) | (1 << 3) | (1 << 4) | (1 << 0);
            }
            else{
                *(pte_entry_addr) = *(pte_entry_addr) | (1 << 4) | (1 << 0);
            }
            asm volatile("invlpg (%0)"::"r" (vaddr));
        }
        else{
            if(access_flags == (PROT_READ | PROT_WRITE)){
                *(pte_entry_addr) = *(pte_entry_addr) | (1 << 3) | (1 << 4) | (1 << 0);
            }
            else{
                *(pte_entry_addr) = *(pte_entry_addr) | (1 << 4) | (1 << 0);
            }
            asm volatile("invlpg (%0)"::"r" (vaddr));
        }
    }
    else{
        return -1;
    }

    return 1;
}