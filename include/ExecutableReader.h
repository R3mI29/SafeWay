#ifndef EXECUTABLEREADER_H_INCLUDED
#define EXECUTABLEREADER_H_INCLUDED
#include <stdbool.h>

int IsExecutable(char *path);
bool FalseExtention(char *path);
int AnalyzeELF(char *path);
int AnalyzePESections(char *path);
int AnalyzeScript(char *path);
int Grade(char *path);


#endif