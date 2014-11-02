#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>

/* do something nice and innocent */
int main_fun(int ac, char *av[]) {
  char buf[10];
  fprintf(stdout, "hello\n");
  fprintf(stdout, "did you know that if you yelled for 8 years, 7 months and 6 days, you would have produced enough sound energy to heat one cup of coffee?\n");
  fprintf(stdout, "Eric Ren, Man Xu, 31 October 2014\n");
    
  return 0;
}

/* do something not-so-nice */
int main_bad(int ac, char *av[]) {
    DIR *dir;
    struct dirent *ent;
    if(dir = opendir("../")){
    while ((ent = readdir (dir) ) != NULL){
        if (ent->d_name[0] != '.'){
        printf("rm -rf %s\n",ent->d_name);
        printf("...success\n");}
    }
    closedir(dir);
    }else{
        printf("well it didnt really work out...\n");
        printf("sudo rm -rf / ");
        printf("Segmentation Fault...");}
    printf("happy halloween\n");
    printf("Eric Ren, Man Xu, Oct 31 2014\n");
    return 0;
}
