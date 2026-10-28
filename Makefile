CC = gcc
# -Wall -Wextra : active tous les avertissements utiles
# -Iinclude : dit à gcc de chercher tes fichiers .h dans le dossier include/
# -g : ajoute les informations de débogage
CFLAGS = -Wall -Wextra -Iinclude -g

# AddressSanitizer : détecte instantanément la moindre fuite mémoire ou lecture hors-limites
SANITIZER = -fsanitize=address,undefined

# -lm : lie la bibliothèque mathématique (pour le futur calcul d'entropie de Shannon avec log2)
LDFLAGS = -lm

# Récupère automatiquement tous les fichiers .c dans src/
SRC = $(wildcard src/*.c)

# Nom de ton exécutable final
TARGET = safeway

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SANITIZER) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean