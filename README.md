# Modified tools to write mifare chinese backdoored cards 

Each script is a part of an open source tool like mfoc or mfclassic, but modified to meet my needs.

The purpose of this work is to adjust the tools that, at least for me did not fully work when trying to write to a backdoored chinese card.

The main modification made to the scripts was to alter and remove some checks that blocked the actual writing. Basically first step is sending the special raw bytes at the card, followed then by iteratively throwing all the rest of the bytes for each section and each block to write them in a raw manner as well, thus rewriting all the blocks of the card, including the uid.

The mfsetuid only writes the specified uid to a card.

# Usage of each tool

gcc mfclassic.c -o mfclassic -lnfc

./mfclassic W a u <file_name>.mfd

gcc mfclone.c -o mfclone -lnfc

./mfclone <file_name>.mfd

gcc mfsetuid.c -o mfsetuid -lnfc

./mfsetuid '88456789'

