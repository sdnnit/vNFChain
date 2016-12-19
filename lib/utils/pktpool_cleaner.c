#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/shm.h>

#define KEY_FILE_PATH_UP    "_pktpool_up.dat"
#define KEY_FILE_PATH_DOWN  "_pktpool_down.dat"


int get_shm(const char *key_path)
{
    key_t key;
    int id;

    key = ftok(key_path, 0xABBAABBA);
    if (key == -1) {
        perror("ftok");
        return -1;
    }

    id = shmget(key, 1, 0);
    if (id < 0) {
        perror("shmget");
    }

    return id;
}


bool get_pkt_pool(int *up_id, int *down_id, const char *dev)
{
    char path[64];

    strcpy(path, dev);
    strcat(path, KEY_FILE_PATH_UP);

    *up_id = get_shm(path);
    if (*up_id < 0) {
        fprintf(stderr, "Can't get up pool\n");
        return false;
    }

    strcpy(path, dev);
    strcat(path, KEY_FILE_PATH_DOWN);

    *down_id = get_shm(path);
    if (*down_id < 0) {
        fprintf(stderr, "Can't get down pool\n");
        return false;
    }

    return true;
}


void clean_pkt_pool(int up_id, int down_id)
{
    shmctl(up_id, IPC_RMID, NULL);
    shmctl(down_id, IPC_RMID, NULL);
}


int main(int argc, char **argv)
{
    int up_id, down_id;

    if (argc != 2) {
        fprintf(stderr, "Usage:%s <dev name>\n", argv[0]);
        return -1;
    }

    if (! get_pkt_pool(&up_id, &down_id, argv[1])) {
        fprintf(stderr, "Can't get packet pools\n");
        return -1;
    }

    clean_pkt_pool(up_id, down_id);

    return 0;
}
