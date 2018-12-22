#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "devices/disk.h"
#include "threads/thread.h"
#include "threads/malloc.h"

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);
struct inode* get_parent_inode (struct dir *dir);
struct dir* get_dir(const char* path);
char *get_filename(const char* path);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  filesys_disk = disk_get (0, 1);

  if (filesys_disk == NULL)
    PANIC ("hd0:1 (hdb) not present, file system initialization failed");

  /* TODO buffer cache initialization */
  buffer_cache_init();

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();
  
  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();

  /* TODO buffer cache done
    - cache[dirty bit == true] -> disk*/
  buffer_cache_done();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool is_dir) 
{
  disk_sector_t inode_sector = 0;

  /* TODO 디렉토리랑 파일이름 가져와서 확인 후 생성 */
  char* file_name = get_filename(name);
  struct dir *dir = get_dir(name);

  bool success = false;

  if(strcmp(file_name, ".") != 0 && strcmp(file_name, "..") != 0){
    success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, is_dir)
                  && dir_add (dir, file_name, inode_sector));
  }
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  free(file_name);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{

  char* file_name = get_filename(name);
  struct dir *dir = get_dir(name);
  struct inode *inode = NULL;

  /* TODO
     case 1) dir 존재
       case 1-1) 파일 이름이 "." -> dir 리턴
       case 1-2) 파일 이름이 ".." -> 부모 dir 열어서 리턴
       case 1-3) root 디렉토리 -> dir 리턴
       case 1-4) 일반적인 파일이름
         case 1-4-1) dir lookup 했을 때 디렉토리 -> 열어서 리턴
         case 1-4-1) dir lookup 했을 때 파일 -> 파일 열어서 리턴
     case 2) dir 없음 -> NULL 리턴
  */

  if (dir != NULL){
    if(strcmp(file_name, ".") == 0){
      free(file_name);
      return (struct file *)dir;
    }
    else if(strcmp(file_name, "..") == 0){
      inode = get_parent_inode(dir);
      if(inode == NULL){
        free(file_name);
        return NULL;
      }
    }
    else if(inode_get_inumber(dir_get_inode(dir)) == ROOT_DIR_SECTOR
            && strlen(file_name) == 0){
      free(file_name);
      return (struct file *)dir;
    }
    else
      dir_lookup (dir, file_name, &inode);
  }

  dir_close (dir);
  free(file_name);
  if(inode == NULL)
    return NULL;

  if(inode_is_dir(inode))
    return (struct file *)dir_open(inode);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char *file_name = get_filename(name);
  struct dir *dir = get_dir(name);

  int result = dir_remove (dir, file_name);

  bool success = dir != NULL && result;
  dir_close (dir);
 
  free(file_name);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();

  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}


/*---------------------------------------------------------------------------------------*/
struct inode*
get_parent_inode (struct dir *dir)
{
  ASSERT(dir != NULL);

  disk_sector_t sector = inode_get_parent(dir_get_inode(dir));
  return inode_open(sector);
}

/*---------------------------------------------------------------------------------------*/
struct dir* 
get_dir(const char* path)
{

  char *path_copy = (char *)malloc(strlen(path)+1);
  strlcpy(path_copy, path, strlen(path)+1);

  char *token, *save_ptr, *prev_token;
  struct dir* dir;
  struct inode* inode;

  if(path_copy[0]=='/' || !thread_current()->dir)
    dir = dir_open_root();
  else
    dir = dir_reopen(thread_current()->dir);

  /* TODO 디렉토리 path 파싱 */
  prev_token = strtok_r(path_copy, "/", &save_ptr);
  for(token = strtok_r(NULL, "/", &save_ptr);
      token != NULL;
      prev_token = token, token = strtok_r(NULL, "/", &save_ptr)){

    if(strcmp(prev_token, ".") == 0)
      continue;
    else if(strcmp(prev_token, "..") == 0){
      if((inode = get_parent_inode(dir)) == NULL)
        return NULL;
    }
    else if(dir_lookup(dir, prev_token, &inode) == false)
      return NULL;

    if(inode_is_dir(inode)){
      dir_close(dir);
      dir = dir_open(inode);
    }
    else
      inode_close(inode);
  }

  free(path_copy);
  return dir;
}

/*---------------------------------------------------------------------------------------*/
bool
filesys_chdir(const char* path)
{
  char *file_name = get_filename(path);
  struct dir *dir = get_dir(path);
  struct inode *inode = NULL;

  /* TODO current directory 설정하기
     case 1) dir 없으면 에러
     case 2) dir 존재
       case 2-1) 파일 이름이 "." -> dir로 설정
       case 2-2) 파일 이름이 ".." 
         -> 현재 디렉토리 닫고 부모 dir로 설정
       case 2-3) root 디렉토리 -> dir로 설정
       case 2-4) 일반적인 파일이름
         -> 현재 디렉토리 닫고 lookup한 dir로 설정
  */

  if(dir == NULL){
    free(file_name);
    return false;
  }

  if(strcmp(file_name, ".") == 0){
    if(thread_current()->dir)
      dir_close(thread_current()->dir);

    thread_current()->dir = dir;
    free(file_name);
    return true;
  }
  else if(strcmp(file_name, "..") == 0){
    // printf("cwd : %d\n", inode_get_inumber(dir_get_inode(dir)));
    inode = get_parent_inode(dir);
    // printf("after cwd : %d\n", inode_get_inumber(inode));
  }
  else if(inode_get_inumber(dir_get_inode(dir)) == ROOT_DIR_SECTOR
          && strlen(file_name) == 0){
    if(thread_current()->dir)
      dir_close(thread_current()->dir);

    thread_current()->dir = dir;
    free(file_name);
    return true;
  }
  else
    dir_lookup (dir, file_name, &inode);

  dir_close(dir);
  dir = dir_open(inode);
  if(dir == NULL){
    free(file_name);
    return false;
  }
  if(thread_current()->dir)
    dir_close(thread_current()->dir);
  thread_current()->dir = dir;

  free(file_name);
  return true;
}

/*---------------------------------------------------------------------------------------*/
char*
get_filename (const char* path)
{
  char *path_copy = (char *)malloc(strlen(path)+1);
  strlcpy(path_copy, path, strlen(path)+1);

  char *token, *save_ptr, *prev_token = "";
  
  for(token = strtok_r(path_copy, "/", &save_ptr);
      token != NULL;
      prev_token = token, token = strtok_r(NULL, "/", &save_ptr))
    continue;

  char *file_name = malloc(strlen(prev_token) + 1);
  strlcpy(file_name, prev_token, strlen(prev_token)+1);

  free(path_copy);

  return file_name;
}
