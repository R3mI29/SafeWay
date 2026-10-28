#ifndef FILESCAN_H_INCLUDED
#define FILESCAN_H_INCLUDED

char *GetPathDownload();
int AskUserPopup(char *filename);
void AskFolderRecursive(char *folder_path);
void HandleFile(char *filepath);
void LockFolderRecursive(const char *folder_path);
void DownloadFileScan_Folder(char *folder_path);
void DownloadFileScan();

#endif