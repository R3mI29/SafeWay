#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ExecutableReader.h>


bool IsExecutable(char *name){
    FILE *f = fopen(name, "rb");
    if (f == NULL)
    {
        return false;
    }
    unsigned char buffer[4]; //Pour lire des octets bruts, toujours utiliser "unsigned char"
    size_t lenght = fread(buffer, 1, 4, f);
    fclose(f);
    if (lenght < 2) // Si il y a moins de 2 octects, ça peut pas êtrre un executable
    {
        return false;
    }
    if (buffer[0] == 'M' && buffer[1] == 'Z')
    {
        return true; //executable Windows
    }
    else if (buffer[0] == '#' && buffer[1] == '!')
    {
        return true; //Script (.sh ou .py)
    }
    else if (buffer[0] == 0x7F && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F')
    {
        return true; //executable Linux
    }
    return false;
}