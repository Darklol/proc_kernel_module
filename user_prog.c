#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>

#define BUFFER_SIZE 8192
#define VM_AREA_STRUCT 0
#define DENTRY_ID 1
#define MAX_PATH_NAME 1024
#define MAX_VM_AREA_PAGES 15
#define OUTPUT_SIZE 4096


int main(int argc, char *argv[])
{
	if (argc != 3) {
		fprintf(stderr, "2 arguments required:  struct={vm_area_struct - 0 | dentry - 1} {pid}\n");
		return 1;
	}
	
	
	int struct_id = atoi(argv[1]);
	char pid_or_path[MAX_PATH_NAME];
	int pop_len = strlen(argv[2]);
	strcpy(pid_or_path, argv[2]);
	
	char info[OUTPUT_SIZE];
	
	if (struct_id != DENTRY_ID && struct_id != VM_AREA_STRUCT) {
		fprintf(stderr, "wrong struct id arguments: 0 for vm_area_struct, 1 for dentry\n");
		return 0;
	}
	
	int fd = open("/proc/my_module", O_RDWR);
	if (fd == -1) {
		fprintf(stderr, "fopen: /proc/my_module opening error\n");
		close(fd);
		return 1;
	}
	
	char buf[BUFFER_SIZE];
	sprintf(buf, "%d %s %d", struct_id, pid_or_path, pop_len);

	if (write(fd, buf, strlen(buf)) == -1) {
		fprintf(stderr, "Writing buffer=\"%s\" to fd=%d failed\n", buf, fd);
		close(fd);
		return 1;
	}

	if (read(fd, info, OUTPUT_SIZE) == -1) {
		fprintf(stderr, "Reading from fd=%d failed\n", fd);
		close(fd);
		return 1;
	}


	puts(info);
	
	close(fd);

	return 0;
}
