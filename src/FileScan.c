#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/limits.h>
#include <unistd.h>
#include <assert.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include "FileScan.h"

char *GetPathDownload(){
    char *home = getenv("HOME");
    if (home == NULL)
    {
        printf("Erreur, la variable HOME, ne vaut rien");
        return NULL;
    }
    char * download = "/Téléchargements";
    char *path = (char*)malloc(sizeof(char)*(strlen(home) + strlen(download) + 1 )); //On ajoute le "+1" pour le "\0"
    if (path == NULL)
    {
        return NULL;
    }
    strcpy(path, home);
    strcat(path, download);
    return path;
}



int AskUserPopup(const char *filename) {
    if (strchr(filename, '\'') != NULL) {
        printf("[!] Alerte : Nom de fichier malveillant detecte (injection shell), suppression directe !\n");
        return 1; 
    }
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "zenity --question "
             "--title='Alerte SafeWay' "
             "--text='Le fichier \"%s\" vient d etre bloque par SafeWay.\n\nVoulez-vous le supprimer definitivement ?' "
             "--ok-label='Supprimer' "
             "--cancel-label='Garder' "
             "--width=400 2>/dev/null",
             filename);
    int ret = system(cmd);
    if (ret == 0) {
        return 1; //Supprime
    }
    return 0; //Garde
}



void DownloadFileScan(){
    char * PathDownload = GetPathDownload();
    int test = chdir(PathDownload);

    assert(test == 0);

    // On récupère le File Descriptor pour parler avec le noyau
    int fd = inotify_init();

    // On lui dit que on veut ou les fichiers et dossiers qui viennent de finir d'écrire (donc fin de téléchargement), ou ceux qui viennent de bouger ou renommé dans ce dossier
    test = inotify_add_watch(fd,PathDownload,(IN_CLOSE_WRITE | IN_MOVED_TO));
    free(PathDownload);
    char buffer[4096];
    while (1)
    {
        ssize_t lenght = read(fd, buffer, sizeof(buffer));
        if (lenght < 0)
        {

        }
        struct inotify_event *event = (struct inotify_event *)buffer;
        chmod(event->name,0400); // On met 0400 et pas 0000 car on veutr le laisser en lecture seul, comme ça SafeWay peut le lire tranquille car le malware ne peut executer
        int choice = AskUserPopup(event->name);
        if (choice == 0)
        {
            if (IsExecutable(event->name))
            {
                chmod(event->name,0755);
            }
            else
            {
                chmod(event->name, 0644);
            }
        }
        else if (choice == 1)
        {
            remove(event->name);
        }
    }
}