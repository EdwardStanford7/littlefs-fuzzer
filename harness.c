/*
 * AFL++ harness for littlefs.
 *
 * The input is a sequence of 4-byte commands.  The low 5 bits of byte 0
 * select an operation; the remaining bytes select paths, sizes, and data.
 * A fresh, correctly formatted filesystem is used for every test case.
 * This concentrates AFL effort on API state transitions while operations 15
 * and 16 also let it exercise recovery from damaged media.
 */
#include "lfs.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 512
#define BLOCK_COUNT 64
#define INPUT_MAX 4096
#define DATA_MAX 256

struct ram_bd {
    uint8_t bytes[BLOCK_SIZE * BLOCK_COUNT];
};

static int bd_read(const struct lfs_config* cfg, lfs_block_t block, lfs_off_t off, void* buffer, lfs_size_t size) {
    struct ram_bd* bd = cfg->context;
    if (block >= BLOCK_COUNT || off > BLOCK_SIZE || size > BLOCK_SIZE - off)
        return LFS_ERR_CORRUPT;
    memcpy(buffer, bd->bytes + block * BLOCK_SIZE + off, size);
    return 0;
}

/* NOR flash can only change a bit from one to zero between erases. */
static int bd_prog(const struct lfs_config* cfg, lfs_block_t block, lfs_off_t off, const void* buffer, lfs_size_t size) {
    struct ram_bd* bd = cfg->context;
    const uint8_t* src = buffer;
    uint8_t* dst;
    lfs_size_t i;

    if (block >= BLOCK_COUNT || off > BLOCK_SIZE || size > BLOCK_SIZE - off)
        return LFS_ERR_CORRUPT;
    dst = bd->bytes + block * BLOCK_SIZE + off;
    for (i = 0; i < size; i++) {
        if ((~dst[i]) & src[i])
            return LFS_ERR_CORRUPT;
        dst[i] &= src[i];
    }
    return 0;
}

static int bd_erase(const struct lfs_config* cfg, lfs_block_t block) {
    struct ram_bd* bd = cfg->context;
    if (block >= BLOCK_COUNT)
        return LFS_ERR_CORRUPT;
    memset(bd->bytes + block * BLOCK_SIZE, 0xff, BLOCK_SIZE);
    return 0;
}

static int bd_sync(const struct lfs_config* cfg) {
    (void)cfg;
    return 0;
}

static const struct lfs_config cfg_template = {
    .read = bd_read,
    .prog = bd_prog,
    .erase = bd_erase,
    .sync = bd_sync,
    .read_size = 16,
    .prog_size = 16,
    .block_size = BLOCK_SIZE,
    .block_count = BLOCK_COUNT,
    .block_cycles = 17,
    .cache_size = 64,
    .lookahead_size = 16,
};

static void path_for(char* path, size_t path_size, unsigned id, int nested) {
    if (nested)
        snprintf(path, path_size, "/d%u/f%u", (id >> 3) & 3, id & 7);
    else
        snprintf(path, path_size, "/f%u", id & 7);
}

static void file_op(lfs_t* lfs, const char* path, unsigned op, unsigned arg, const uint8_t* data) {
    lfs_file_t file;
    struct lfs_attr attr = {.type = (uint8_t)(arg >> 8), .buffer = (void*)data, .size = (arg & 15) + 1};
    struct lfs_file_config file_cfg = {.attrs = &attr, .attr_count = 1};
    uint8_t buffer[DATA_MAX];
    lfs_ssize_t result;

    if (lfs_file_opencfg(lfs, &file, path, LFS_O_RDWR | LFS_O_CREAT, &file_cfg) != 0)
        return;
    switch (op) {
    case 0: /* append/write */
        (void)lfs_file_seek(lfs, &file, 0, LFS_SEEK_END);
        (void)lfs_file_write(lfs, &file, data, (arg & 63) + 1);
        break;
    case 1: /* overwrite at an interesting offset */
        (void)lfs_file_seek(lfs, &file, arg % 768, LFS_SEEK_SET);
        (void)lfs_file_write(lfs, &file, data, (arg & 127) + 1);
        break;
    case 2:
        (void)lfs_file_seek(lfs, &file, arg % 768, LFS_SEEK_SET);
        result = lfs_file_read(lfs, &file, buffer, (arg & 127) + 1);
        (void)result;
        break;
    case 3:
        (void)lfs_file_truncate(lfs, &file, arg % 768);
        break;
    default:
        (void)lfs_file_sync(lfs, &file);
        break;
    }
    (void)lfs_file_close(lfs, &file);
}

static void list_dir(lfs_t* lfs, const char* path, unsigned limit) {
    lfs_dir_t dir;
    struct lfs_info info;
    unsigned i;
    if (lfs_dir_open(lfs, &dir, path) != 0)
        return;
    for (i = 0; i < limit; i++) {
        int err = lfs_dir_read(lfs, &dir, &info);
        if (err <= 0)
            break;
    }
    (void)lfs_dir_close(lfs, &dir);
}

static void remount(lfs_t* lfs, const struct lfs_config* cfg, int* mounted) {
    if (*mounted)
        (void)lfs_unmount(lfs);
    memset(lfs, 0, sizeof(*lfs));
    *mounted = lfs_mount(lfs, cfg) == 0;
}

static void run_case(const uint8_t* input, size_t length) {
    struct ram_bd bd;
    struct lfs_config cfg = cfg_template;
    lfs_t lfs;
    int mounted = 0;
    size_t pos;

    memset(&bd, 0xff, sizeof(bd));
    cfg.context = &bd;
    memset(&lfs, 0, sizeof(lfs));
    if (lfs_format(&lfs, &cfg) != 0 || lfs_mount(&lfs, &cfg) != 0)
        abort(); /* A blank valid device must always format and mount. */
    mounted = 1;

    for (pos = 0; pos + 3 < length; pos += 4) {
        unsigned code = input[pos] & 31;
        unsigned id = input[pos + 1];
        unsigned arg = ((unsigned)input[pos + 2] << 8) | input[pos + 3];
        char a[20], b[20], dir[8];
        uint8_t data[DATA_MAX];
        size_t data_length = length - pos;
        if (data_length > sizeof(data))
            data_length = sizeof(data);
        memset(data, 0, sizeof(data));
        memcpy(data, input + pos, data_length);
        if (!mounted && code != 18 && code != 19)
            continue;
        path_for(a, sizeof(a), id, input[pos] & 0x20);
        path_for(b, sizeof(b), id + 1, input[pos] & 0x20);
        snprintf(dir, sizeof(dir), "/d%u", (id >> 3) & 3);

        switch (code) {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
            file_op(&lfs, a, code, arg, data);
            break;
        case 5:
            (void)lfs_mkdir(&lfs, dir);
            break;
        case 6:
            (void)lfs_remove(&lfs, a);
            break;
        case 7:
            (void)lfs_remove(&lfs, dir);
            break;
        case 8:
            (void)lfs_rename(&lfs, a, b);
            break;
        case 9:
            (void)lfs_setattr(&lfs, a, (uint8_t)arg, data, (arg & 15) + 1);
            break;
        case 10: {
            uint8_t value[16];
            (void)lfs_getattr(&lfs, a, (uint8_t)arg, value, sizeof(value));
            break;
        }
        case 11:
            (void)lfs_removeattr(&lfs, a, (uint8_t)arg);
            break;
        case 12:
            list_dir(&lfs, "/", (arg & 15) + 1);
            break;
        case 13:
            list_dir(&lfs, dir, (arg & 15) + 1);
            break;
        case 14: {
            struct lfs_info info;
            (void)lfs_stat(&lfs, a, &info);
            break;
        }
        case 15:
            (void)lfs_fs_size(&lfs);
            (void)lfs_fs_gc(&lfs);
            break;
        case 16: /* Raw 1->0 corruption, followed by a recovery attempt. */
            bd.bytes[(arg % BLOCK_COUNT) * BLOCK_SIZE + (id % BLOCK_SIZE)] &= input[pos + 3];
            remount(&lfs, &cfg, &mounted);
            break;
        case 17:
            remount(&lfs, &cfg, &mounted);
            break;
        case 18:
            if (mounted)
                (void)lfs_unmount(&lfs);
            mounted = 0;
            break;
        case 19:
            if (!mounted)
                remount(&lfs, &cfg, &mounted);
            break;
        case 20:
            if (mounted) {
                (void)lfs_unmount(&lfs);
                memset(&lfs, 0, sizeof(lfs));
                (void)lfs_format(&lfs, &cfg);
                mounted = lfs_mount(&lfs, &cfg) == 0;
            }
            break;
        default:
            break;
        }
    }
    if (mounted)
        (void)lfs_unmount(&lfs);
}

int main(void) {
    static uint8_t input[INPUT_MAX];
    size_t length = fread(input, 1, sizeof(input), stdin);
    run_case(input, length);
    return 0;
}
