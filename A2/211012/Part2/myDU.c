#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/wait.h>

unsigned long directorySize(char* path){

     struct stat st;
     int fd[2];
     pid_t pid;
     if(pipe(fd)==-1){
          fprintf(stderr, "Unable to execute\n");
          exit(1);
     }

     if(lstat(path, &st)==-1){
          fprintf(stderr, "Unable to execute\n");
          exit(1);
     }
     if(S_ISREG(st.st_mode)){
         return 0;
     }
     else if(S_ISLNK(st.st_mode)){
          return 0;
     }
     pid = fork();
     if(pid==-1){
          fprintf(stderr, "Unable to execute\n");
          exit(1);
     }
     else if(pid == 0){
          close(fd[0]);
          dup2(fd[1], 1); 
          char *cmd[] = {"./myDU", path, NULL};
          if(execvp("./myDU", cmd)==-1){
               fprintf(stderr, "Unable to execute\n");
               exit(1);
          }
          close(fd[1]);  
     }
     else{
          close(fd[1]);
          char sbuf[1000];
          int status;
          waitpid(pid, &status, 0);
          // if(exit_child == -1){
          //      fprintf(stderr, "Unable to execute\n");
          //      exit(1);
          // }
          // if(WIFEXITED(status)){
          //      // fprintf(stderr, "Unable to execute\n");
          //      exit(1);
          // }
          ssize_t len = read(fd[0], sbuf, sizeof(sbuf) - 1);
          sbuf[len]='\0';
          close(fd[0]);
          unsigned long size = strtoul(sbuf, NULL, 10);
          return size;
     }
}

int main(int argc, char * argv[]){

     if(argc!=2){
          fprintf(stderr, "Unable to execute\n");
          exit(1);
     }

     char *root = argv[1];
     DIR *dir = opendir(root);
     struct dirent *entry;

     if(dir==NULL){
          fprintf(stderr, "Unable to execute\n");
          exit(1);
     }

     struct stat st;

     if(lstat(root, &st)==-1){
          fprintf(stderr, "Unable to execute\n");
          exit(1);
     }
     unsigned long totalsize = st.st_size;

     while((entry = readdir(dir))!=NULL){
          if( (entry->d_name[0]=='.' && entry->d_name[1]=='.' && entry->d_name[2]=='\0') || (entry->d_name[0]=='.' && entry->d_name[1]=='\0')) continue;

          char path[1000];
          int len = snprintf(path, sizeof(path), "%s/%s", root, entry->d_name);
          path[len] = '\0';

          struct stat st;
          if(lstat(path, &st)==-1){
               fprintf(stderr, "Unable to execute\n");
               exit(1);
          }

          if(S_ISDIR(st.st_mode)){
               totalsize+=directorySize(path);
          }

          else if(S_ISREG(st.st_mode)){
               totalsize+=st.st_size;
          }

          else if(S_ISLNK(st.st_mode)){
               
               char sbuf[1000];

               ssize_t link_size = readlink(path, sbuf, sizeof(sbuf) - 1);
               if (link_size == -1) {
                    fprintf(stderr, "Unable to execute\n");
                    exit(1);
               }

               sbuf[link_size] = '\0';

               char linkpath[1000];
               int len = snprintf(linkpath, sizeof(linkpath), "%s/%s", root, sbuf);
               linkpath[len] = '\0';

               struct stat symlink_st;
               if(lstat(linkpath, &symlink_st)==-1){
                    fprintf(stderr, "Unable to execute\n");
                    exit(1);
               }

               if(S_ISDIR(symlink_st.st_mode)){
                    totalsize+=directorySize(linkpath);
               }

               else if(S_ISREG(symlink_st.st_mode)){
                    totalsize+=symlink_st.st_size;
               }
               
               else if(S_ISLNK(symlink_st.st_mode)){
                    while(S_ISLNK(symlink_st.st_mode)){
                         char linkpath1[1000];
                         char sbuf[1000];
                         ssize_t link_size = readlink(linkpath, sbuf, sizeof(sbuf) - 1);
                         int linkpathlen = strlen(linkpath);
                         for(int i=linkpathlen-1; i>=0; i--){
                              if(linkpath[i]=='/'){
                                   linkpath[i]='\0';
                                   break;
                              }
                         }
                         strcpy(linkpath1, linkpath);
                         strcat(linkpath1, "/");
                         
                         if (link_size == -1) {
                              fprintf(stderr, "Unable to execute\n");
                              exit(1);
                         }
                         sbuf[link_size] = '\0';
                         strcat(linkpath1, sbuf);
                         int len = strlen(linkpath) + 1 + link_size;
                         linkpath1[len]='\0';

                         if(lstat(linkpath1, &symlink_st)==-1){
                              fprintf(stderr, "Unable to execute\n");
                              exit(1);
                         }

                         strcpy(linkpath,linkpath1);
                         int linkpath1len = strlen(linkpath1);
                         linkpath[linkpath1len]='\0';
                    }
                    if(S_ISDIR(symlink_st.st_mode)){
                         totalsize+=directorySize(linkpath);
                    }
                    else if(S_ISREG(symlink_st.st_mode)){
                         totalsize+=symlink_st.st_size;
                    }
               }
          }
               
     }


     
     if(totalsize < 0) fprintf(stderr, "Unable to execute\n");
     printf("%lu", totalsize);

     return 0;

}
