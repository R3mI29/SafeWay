#include <stdlib.h>
#include <strings.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ExecutableReader.h>



bool IsExecutable(char *path){
    FILE *f = fopen(path, "rb");
    if (f == NULL)
    {
        return 0;
    }
    unsigned char buffer[4]; //Pour lire des octets bruts, toujours utiliser "unsigned char"
    size_t lenght = fread(buffer, 1, 4, f);
    fclose(f);
    if (lenght < 2) // Si il y a moins de 2 octects, ça peut pas êtrre un executable
    {
        return 0;
    }
    if (buffer[0] == 'M' && buffer[1] == 'Z')
    {
        return 1; //executable Windows
    }
    else if (buffer[0] == '#' && buffer[1] == '!')
    {
        return 3; //Script (.sh ou .py)
    }
    else if (buffer[0] == 0x7F && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F')
    {
        return 2; //executable Linux
    }
    return 0;
}




bool FalseExtention(char *path){
    if (IsExecutable(path))
    {
        char *ext = strrchr(path, '.'); // On cherche le dernier point de la signature
        if (ext == NULL) {
            return false; // Pas d'extension du tout (normal pour un exécutable Linux comme)
        }
        const char *bad_extensions[] = {
            ".pdf", ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg",
            ".mp3", ".mp4", ".wav", ".avi", ".mkv", ".mov",
            ".zip", ".rar", ".7z", ".tar", ".gz", ".iso"
        };
        int nb_ext = sizeof(bad_extensions) / sizeof(bad_extensions[0]);
        for (int i = 0; i < nb_ext; i++) {
            if (strcasecmp(ext, bad_extensions[i]) == 0) {
                return true;
            }
        }
    }
    else
    {
        return false;
    }
    return false;
}


int AnalyzePESections(char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return 0;
    }

    // On verifie d'abord que c'est bien un executable Windows "MZ"
    if (IsExecutable(path) != 1) {
        fclose(f);
        return 0; // Ce n'est pas un fichier Windows (.exe), pas d'en-tete PE
    }

    // Lecture de l'adresse du PE Header a l'octet 0x3C (60)
    unsigned int PE_HEADER = 0;
    fseek(f, 0x3C, SEEK_SET);
    fread(&PE_HEADER, sizeof(unsigned int), 1, f);
    fseek(f, PE_HEADER, SEEK_SET);

    // Verification de la signature "PE\0\0"
    unsigned char pe_sig[4] = {0};
    fread(pe_sig, 1, 4, f);
    if (pe_sig[0] != 'P' || pe_sig[1] != 'E' || pe_sig[2] != 0 || pe_sig[3] != 0) {
        fclose(f);
        return 0;
    }

    unsigned short NB_SECTION = 0;
    unsigned short SIZE_OPT_HEADER = 0;

    fseek(f, 2, SEEK_CUR); // Saute "Machine" (2 octets)
    fread(&NB_SECTION, sizeof(unsigned short), 1, f);

    fseek(f, 12, SEEK_CUR); // Saute "TimeDateStamp" + "SymbolTable" + "NbSymbols" (12 octets)
    fread(&SIZE_OPT_HEADER, sizeof(unsigned short), 1, f);

    fseek(f, 2, SEEK_CUR); // Saute "Characteristics" du COFF Header (2 octets)
    fseek(f, SIZE_OPT_HEADER, SEEK_CUR); // Saute l'Optional Header : on est pile devant la première section 

    // Boucle sur chaque section (40 octets par section)
    int score = 0;
    for (int i = 0; i < NB_SECTION; i++) {
        char sec_name[9];
        unsigned int virtual_size = 0;
        unsigned int raw_size = 0;
        unsigned int characteristics = 0;

        fread(sec_name, 1, 8, f);
        fread(&virtual_size, sizeof(unsigned int), 1, f);
        fseek(f, 4, SEEK_CUR);
        fread(&raw_size, sizeof(unsigned int), 1, f);
        fseek(f, 16, SEEK_CUR);
        fread(&characteristics, sizeof(unsigned int), 1, f);

        // Test 1 : Section Write (0x80000000) ET Execute (0x20000000) en meme temps
        if ((characteristics & 0x20000000) && (characteristics & 0x80000000)) {
            score += 50;
        }

        // Test 2 : Nom de packer connu (UPX, VMProtect, ASPack)
        if (strncmp(sec_name, "UPX", 3) == 0 || strncmp(sec_name, ".vmp", 4) == 0 || strncmp(sec_name, ".aspack", 7) == 0) {
            score += 30;
        }

        // Test 3 : Section executable vide sur le disque (raw_size == 0) mais presente en RAM (virtual_size > 0)
        if ((characteristics & 0x20000000) && raw_size == 0 && virtual_size > 0) {
            score += 30;
        }
    }

    fclose(f);
    return score;
}



int AnalyzeELF(char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return 0;
    }

    // 1. On verifie que c'est bien un executable Linux ELF 64-bits (buffer[4] == 2)
    unsigned char magic[5] = {0};
    if (fread(magic, 1, 5, f) < 5 || magic[0] != 0x7F || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F' || magic[4] != 2) {
        fclose(f);
        return 0;
    }

    // 2. On lit l'adresse des segments (octet 32) et leur nombre (octet 56)
    unsigned long ph_offset = 0; // 8 octets sur Linux 64-bits
    unsigned short ph_num = 0;   // 2 octets

    fseek(f, 32, SEEK_SET);
    fread(&ph_offset, sizeof(unsigned long), 1, f);

    fseek(f, 56, SEEK_SET);
    fread(&ph_num, sizeof(unsigned short), 1, f);

    // 3. On saute au debut des segments
    fseek(f, ph_offset, SEEK_SET);

    int score = 0;
    for (int i = 0; i < ph_num; i++) {
        unsigned int flags = 0;

        fseek(f, 4, SEEK_CUR); // On saute p_type (4 octets)
        fread(&flags, sizeof(unsigned int), 1, f); // On lit les permissions (4 octets)
        fseek(f, 48, SEEK_CUR); // On saute le reste du segment (56 - 8 = 48 octets)

        // Si le segment a le bit Execute (1) ET le bit Write (2) en meme temps (W + X) !
        if ((flags & 1) && (flags & 2)) {
            score += 50;
        }
    }

    fclose(f);
    return score;
}


int AnalyzeScript(char *path){

}



int Grade(char *path){
    int GRADE = 0;
    if (IsExecutable != 0)
    {
        if (FalseExtention(path))
        {
            return 100;
        }
        if (IsExecutable == 1) // Executable Windows
        {
            GRADE += AnalyzePESections(path);
        }
        else if (IsExecutable == 2) // Executable Linux
        {
            GRADE += AnalyzeELF(path);
        }
        else if (IsExecutable == 3) // Script
        {
            GRADE += AnalyzeScript(path);
        }
        if (GRADE > 100) 
        {
            return 100;
        }
        return GRADE;
    }
    return 0;
}