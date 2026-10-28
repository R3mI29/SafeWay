#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <FileScan.h>
#include <ExecutableReader.h>

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
int AskUserPopup(char *filename) {
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


void HandleFile(char *filepath) {
    int choice = AskUserPopup(filepath);
    if (choice == 0) {
        if (IsExecutable(filepath)) 
        {
            chmod(filepath, 0755);
        } 
        else 
        {
            chmod(filepath, 0644);
        }
    } 
    else if (choice == 1) 
    {
        remove(filepath);
    }
}



void LockFolderRecursive(const char *folder_path) {
    DIR *dir = opendir(folder_path);
    if (dir == NULL) 
    {
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) 
    {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {
            char full_path[4096];
            snprintf(full_path, sizeof(full_path), "%s/%s", folder_path, entry->d_name);
            struct stat st;
            if (stat(full_path, &st) == 0) //On attribut à st les caractéristique de l'élément que l'on regarde actuelement 
            {
                if (S_ISDIR(st.st_mode)) // On demande avec une fonction native de <sys/stat.h> si c'est un dossier oou un fichier 
                {
                    LockFolderRecursive(full_path); // Sous-dossier : appel recursif
                }
                else 
                {
                    chmod(full_path, 0400); // Fichier : verrouillage immediat
                }
            }
        }
    }
    closedir(dir);
}


void AskFolderRecursive(char *folder_path) {
    DIR *dir = opendir(folder_path);
    if (dir == NULL) {
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) 
    {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {
            char full_path[4096];
            snprintf(full_path, sizeof(full_path), "%s/%s", folder_path, entry->d_name);
            struct stat st;
            if (stat(full_path, &st) == 0) //On attribut à st les caractéristique de l'élément que l'on regarde actuelement 
            {
                if (S_ISDIR(st.st_mode)) // On demande avec une fonction native de <sys/stat.h> si c'est un dossier oou un fichier 
                {
                    AskFolderRecursive(full_path);
                }
                else 
                {
                    HandleFile(full_path);
                }
            }
        }
    }
    closedir(dir);
}


void DownloadFileScan_Folder(char *folder_path){
    LockFolderRecursive(folder_path);
    AskFolderRecursive(folder_path);
}


void DownloadFileScan() {
    char *PathDownload = GetPathDownload();
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

    int fd = inotify_init();
    if (fd < 0) 
    {
        printf("Erreur : inotify_init a echoue\n");
        free(PathDownload);
        return;
    }

    test = inotify_add_watch(fd, PathDownload, (IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE));
    free(PathDownload); // Plus besoin de la chaine PathDownload en memoire
    if (test < 0) 
    {
        printf("Erreur : inotify_add_watch a echoue\n");
        close(fd);
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


        // Passe 1 : on verrouille TOUS les fichiers et contenus de dossiers recus avant d'ouvrir le moindre pop-up
        ssize_t i = 0;
        while (i < length) 
        {
            struct inotify_event *event = (struct inotify_event *)(buffer + i);
            if (event->len > 0) 
            {
                if (event->mask & IN_ISDIR) 
                {
                    // C'est un dossier : on verrouille recursivement tous les fichiers qu'il contient
                    LockFolderRecursive(event->name);
                } 
                else if (event->mask & (IN_CLOSE_WRITE | IN_MOVED_TO)) 
                {
                    // C'est un fichier qui vient de finir d'etre ecrit ou d'etre deplace
                    chmod(event->name, 0400);
                }
            }
            i = i + sizeof(struct inotify_event) + event->len;
        }



        // Passe 2 : on demande a l'utilisateur pour chaque fichier ou contenu de dossier
        i = 0;
        while (i < length) 
        {
            struct inotify_event *event = (struct inotify_event *)(buffer + i);
            if (event->len > 0) 
            {
                if (event->mask & IN_ISDIR) 
                {
                    AskFolderRecursive(event->name);
                } 
                else if (event->mask & (IN_CLOSE_WRITE | IN_MOVED_TO)) 
                {
                    HandleFile(event->name);
                }
            }
            i = i + sizeof(struct inotify_event) + event->len;
        }
    }
    close(fd);
}