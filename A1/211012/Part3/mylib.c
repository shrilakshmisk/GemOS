#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <math.h>
#include "mylib.h"

void *head = NULL;
unsigned long _4MB = 4 * 1024 * 1024;

void *memalloc(unsigned long size){

	printf("memalloc() called\n");

	// return NULL if size is 0
	if(size == 0) return NULL;

	// Calculate the required size = reqd
	unsigned long reqd = (size / 8) * 8;
	unsigned long mod8 = size % 8;
	if(mod8 != 0){
		reqd += 8;
	}
	reqd += 8; 

	// if you memfree it later
	if (reqd < 24) reqd = 24; 

	// Declare the return pointer - allocated pointer
	void *all_ptr;

	// Traversing the linked list
	void *temp = head;
	while(temp){
		unsigned long temp_size = *((unsigned long *)(temp));
		if(temp_size >= reqd){
			break;
		}
		temp = *((void **)(temp + 8));
	}

	unsigned long free_chunk_size;

	if(temp == NULL){ 
		//mmap() required
		unsigned long mmap_reqd = (reqd / _4MB) * _4MB;
		unsigned long mod_4MB = reqd % _4MB;
		if(mod_4MB != 0){
			mmap_reqd += _4MB;
		}

		void *ini_ptr = mmap(NULL, mmap_reqd, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		all_ptr = ini_ptr;
		free_chunk_size = mmap_reqd;
	}

	else{
		all_ptr = temp;
		free_chunk_size = *((unsigned long *)(temp));
	}

	unsigned long free_remaining_size = free_chunk_size - reqd;
	if(free_remaining_size >= 24){
		if(temp == NULL){ //mmap, only insertion
			void *free_ptr = all_ptr + reqd;
			*((unsigned long *)(free_ptr)) = free_remaining_size;
			*((unsigned long *)(all_ptr)) = reqd;
			if(head == NULL){
				*((void **)(free_ptr + 8)) = NULL;
				*((void **)(free_ptr + 16)) = NULL;
				
			}
			else{ //insert first
				*((void **)(free_ptr + 16)) = NULL;
				*((void **)(free_ptr + 8)) = head;
				*((void **)(head + 16)) = free_ptr;
				
			}
			head = free_ptr;

		}
		else{ //remove from linked list
			if (*((void **)(temp + 8)) == NULL && *((void **)(temp + 16)) == NULL){
				head = NULL;
			}
			else if (*((void **)(temp + 8)) == NULL){
				*((void **)(*((void **)(temp + 16)) + 8)) = NULL;
			}
			else if (*((void **)(temp + 16)) == NULL){
				head = *((void **)(temp + 8));
				*((void **)(*((void **)(temp + 8)) + 16)) = NULL;
			}
			else{
				*((void **)(*((void **)(temp + 16)) + 8)) = *((void **)(temp + 8));
				*((void **)(*((void **)(temp + 8)) + 16)) = *((void **)(temp + 16));
			}

			//insert
			void *free_ptr = all_ptr + reqd;
			*((unsigned long *)(free_ptr)) = free_remaining_size;
			*((unsigned long *)(all_ptr)) = reqd;
			if(head == NULL){
				*((void **)(free_ptr + 8)) = NULL;
				*((void **)(free_ptr + 16)) = NULL;
			}
			else{ //insert first
				*((void **)(free_ptr + 16)) = NULL;
				*((void **)(free_ptr + 8)) = head;
				*((void **)(head + 16)) = free_ptr;
				
			}
			head = free_ptr;

		}
	}
	else{ //remove from linked list
		*((unsigned long *)(all_ptr)) = free_chunk_size;
		if(temp != NULL){
			if (*((void **)(temp + 8)) == NULL && *((void **)(temp + 16)) == NULL){
				head = NULL;
			}
			else if (*((void **)(temp + 8)) == NULL){
				*((void **)(*((void **)(temp + 16)) + 8)) = NULL;
			}
			else if (*((void **)(temp + 16)) == NULL){
				head = *((void **)(temp + 8));
				*((void **)(*((void **)(temp + 8)) + 16)) = NULL;
			}
			else{
				*((void **)(*((void **)(temp + 16)) + 8)) = *((void **)(temp + 8));
				*((void **)(*((void **)(temp + 8)) + 16)) = *((void **)(temp + 16));
			}
		}
	}
	return all_ptr + 8;
}

int memfree(void *ptr){   
	printf("memfree() called\n");
	if(ptr==NULL) return -1;

	int r=0; 
	unsigned long right_size, left_size;
	//right neighbour
	void *left_comp = ptr-8;
	unsigned long free_size = *((unsigned long *)(left_comp));
	void *right_comp = left_comp + free_size;
	void *temp = head;
	while(temp != NULL){
		if(temp == right_comp){
			r = 1;
			right_size = *((unsigned long *)(right_comp));
			void *right_start = right_comp;
			if (*((void **)(right_start + 8)) == NULL && *((void **)(right_start + 16)) == NULL){
				head = NULL;
			}
			else if (*((void **)(right_start + 16)) == NULL){
				head = *((void **)(right_start + 8));
				*((void **)(*((void **)(right_start + 8)) + 16)) = NULL;
			}
			else if (*((void **)(right_start + 8)) == NULL){
				*((void **)(*((void **)(right_start + 16)) + 8)) = NULL;
			}
			else{
				*((void **)(*((void **)(right_start + 16)) + 8)) = *((void **)(right_start + 8));
				*((void **)(*((void **)(right_start + 8)) + 16)) = *((void **)(right_start + 16));
			}
			break;
		}
		temp=*((void **)(temp + 8));
	}
	unsigned long total_size;
	void *start;
	//left neighbour
	temp = head;
	while(temp!=NULL){
		unsigned long temp_size = *((unsigned long *)(temp));
		if(temp + temp_size == left_comp){
			left_size = temp_size;
			void *left_start = left_comp - left_size;
			//remove from linked list
			if (*((void **)(left_start + 8)) == NULL && *((void **)(left_start + 16)) == NULL){
				head = NULL;
			}
			else if (*((void **)(left_start + 16)) == NULL){
				head = *((void **)(left_start + 8));
				*((void **)(*((void **)(left_start + 8)) + 16)) = NULL;
			}
			else if (*((void **)(left_start + 8)) == NULL){
				*((void **)(*((void **)(left_start + 16)) + 8)) = NULL;
			}
			else{
				*((void **)(*((void **)(left_start + 16)) + 8)) = *((void **)(left_start + 8));
				*((void **)(*((void **)(left_start + 8)) + 16)) = *((void **)(left_start + 16));
			}

			if(r){ //coalesce
				total_size = free_size + left_size + right_size;
				start = left_comp - left_size;
			}
			else{
				total_size = free_size + left_size;
				start = left_comp - left_size;
			}
			break;
		}
		temp=*((void **)(temp + 8));
	}
	if(temp==NULL){
		if(r){
			total_size = free_size + right_size;
			start = left_comp;
		}
		else{
			total_size = free_size;
			start = left_comp;
		}
	}

	*((unsigned long *)(start)) = total_size;
	//insert
	if(head==NULL){
		*((void **)(start + 8)) = NULL;	
		*((void **)(start + 16)) = NULL; 
	}
	else{
		*((void **)(start + 8)) = head;
		*((void **)(start + 16)) = NULL;
		*((void **)(head + 16)) = start;
	}
	head = start;

	return 0;
} 

