#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/wait.h>
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



// Retourne 1 pour supprimer, 0 pour garder, -1 si on n'a pas pu avoir de reponse
int AskUserPopup(const char *filename) {
    // Une apostrophe dans le nom casserait la commande shell (injection possible).
    // On ne supprime pas pour autant : on laisse le fichier verrouille.
    if (strchr(filename, '\'') != NULL) {
        printf("[!] Nom de fichier avec une apostrophe : popup impossible, le fichier reste verrouille.\n");
        return -1;
    }
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "zenity --question --no-markup "
             "--title='Alerte SafeWay' "
             "--text='Le fichier \"%s\" vient d etre bloque par SafeWay.\n\nVoulez-vous le supprimer definitivement ?' "
             "--ok-label='Supprimer' "
             "--cancel-label='Garder' "
             "--width=400 2>/dev/null",
             filename);
    int ret = system(cmd);

    // zenity renvoie 0 si on clique sur "Supprimer", 1 si on clique sur "Garder".
    // Tout autre cas (zenity pas installe, plante...) : on ne decide rien.
    if (WIFEXITED(ret) && WEXITSTATUS(ret) == 0) {
        return 1; //Supprime
    }
    if (WIFEXITED(ret) && WEXITSTATUS(ret) == 1) {
        return 0; //Garde
    }
    return -1;
}



void DownloadFileScan(){
    char * PathDownload = GetPathDownload();
    if (PathDownload == NULL)
    {
        return;
    }
    int test = chdir(PathDownload);
    if (test != 0)
    {
        printf("Erreur : impossible d'aller dans le dossier Telechargements\n");
        free(PathDownload);
        return;
    }

    // On récupère le File Descriptor pour parler avec le noyau
    int fd = inotify_init();
    if (fd < 0)
    {
        printf("Erreur : inotify_init a echoue\n");
        free(PathDownload);
        return;
    }

    // On lui dit que on veut ou les fichiers et dossiers qui viennent de finir d'écrire (donc fin de téléchargement), ou ceux qui viennent de bouger ou renommé dans ce dossier
    test = inotify_add_watch(fd,PathDownload,(IN_CLOSE_WRITE | IN_MOVED_TO));
    free(PathDownload); // On libere ICI, apres le dernier endroit ou on s'en sert
    if (test < 0)
    {
        printf("Erreur : inotify_add_watch a echoue\n");
        return;
    }

    char buffer[4096];
    while (1)
    {
        ssize_t length = read(fd, buffer, sizeof(buffer));
        if (length < 0)
        {
            printf("Erreur de lecture\n");
            break;
        }

        // Un seul read() peut contenir plusieurs evenements les uns a la suite des autres.
        // Chaque evenement fait sizeof(struct inotify_event) + event->len octets,
        // donc on avance de cette taille pour arriver a l'evenement suivant.

        // Passe 1 : on verrouille TOUS les fichiers recus avant de poser la moindre question
        ssize_t i = 0;
        while (i < length)
        {
            struct inotify_event *event = (struct inotify_event *)(buffer + i);
            if (!(event->mask & IN_ISDIR)) // On ignore les dossiers
            {
                chmod(event->name,0400); // On met 0400 et pas 0000 car on veut le laisser en lecture seul, comme ça SafeWay peut le lire tranquille car le malware ne peut executer
            }
            i = i + sizeof(struct inotify_event) + event->len;
        }

        // Passe 2 : on demande a l'utilisateur pour chaque fichier
        i = 0;
        while (i < length)
        {
            struct inotify_event *event = (struct inotify_event *)(buffer + i);
            if (!(event->mask & IN_ISDIR))
            {
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
                // Si choice vaut -1 on ne fait rien : le fichier reste en 0400
            }
            i = i + sizeof(struct inotify_event) + event->len;
        }
    }
}